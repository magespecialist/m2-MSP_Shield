<?php
/**
 * MageSpecialist
 *
 * NOTICE OF LICENSE
 *
 * This source file is subject to the Open Software License (OSL 3.0)
 * that is bundled with this package in the file LICENSE.txt.
 * It is also available through the world-wide-web at this URL:
 * http://opensource.org/licenses/osl-3.0.php
 * If you did not receive a copy of the license and are unable to
 * obtain it through the world-wide-web, please send an email
 * to info@magespecialist.it so we can send you a copy immediately.
 *
 * @category   MSP
 * @package    MSP_Shield
 * @copyright  Copyright (c) 2017 Skeeller srl (http://www.magespecialist.it)
 * @license    http://opensource.org/licenses/osl-3.0.php  Open Software License (OSL 3.0)
 */

namespace MSP\Shield\Model\Detector;

use Magento\Framework\App\ResourceConnection;
use MSP\Shield\Api\DetectorInterface;
use MSP\Shield\Api\DetectorRegexInterface;
use MSP\Shield\Api\ThreatInterface;
use MSP\Shield\Model\CacheType;
use PhpMyAdmin\SqlParser\Lexer;
use MSP\Shield\Api\ThreatInterfaceFactory;
use PhpMyAdmin\SqlParser\Parser;
use PhpMyAdmin\SqlParser\Statement;
use PhpMyAdmin\SqlParser\Statements\SelectStatement;
use PhpMyAdmin\SqlParser\Token;

class Sqli implements DetectorInterface
{
    const CODE = 'sqli';
    const RESCODE_SQLI_FRAGMENT = 'sqli_fragment';
    const RESCODE_SQLI_COMMAND = 'sqli_command';
    const RESCODE_SQLI_SIMULATED = 'sqli_simulated';

    const CACHE_KEY_MAGENTO_TABLES = 'sqli/table_names';

    protected $magentoTables = null;

    /**
     * @var DetectorRegexInterface
     */
    private $detectorRegex;

    /**
     * @var ThreatInterfaceFactory
     */
    private $threatInterfaceFactory;

    /**
     * @var CacheType
     */
    private $cacheType;

    /**
     * @var ResourceConnection
     */
    private $resourceConnection;

    public function __construct(
        DetectorRegexInterface $detectorRegex,
        ThreatInterfaceFactory $threatInterfaceFactory,
        CacheType $cacheType,
        ResourceConnection $resourceConnection
    )
    {
        $this->detectorRegex = $detectorRegex;
        $this->threatInterfaceFactory = $threatInterfaceFactory;
        $this->cacheType = $cacheType;
        $this->resourceConnection = $resourceConnection;
    }

    /**
     * Get detector codename
     * @return string
     */
    public function getCode()
    {
        return static::CODE;
    }

    /**
     * Get inject simulations
     * @param string $fieldValue
     * @return array
     */
    protected function getInjectionSimulations($fieldValue)
    {
        return [
            $fieldValue => [
                'start' => 0,
                'end' => 0,
                'quoted' => false,
                'empty' => true,
            ],
            "select * from mynonexistenttable where mynonexistentfield=$fieldValue" => [
                'start' => 12,
                'end' => 0,
                'quoted' => false,
                'empty' => false,
                'field' => 'mynonexistentfield',
            ],
            "select * from mynonexistenttable where mynonexistentfield='$fieldValue'" => [
                'start' => 13,
                'end' => 0,
                'quoted' => true,
                'empty' => false,
                'field' => 'mynonexistentfield',
            ],
            "select * from mynonexistenttable where mynonexistentfield='foo' $fieldValue" => [
                'start' => 14,
                'end' => 0,
                'quoted' => false,
                'empty' => false,
            ]
        ];
    }

    /**
     * Analyze comment
     * @param array $tokens
     * @param int $position
     * @return int
     */
    protected function analyzeComment(array $tokens, $position)
    {
        /** @var Token $token */
        $token = $tokens[$position];

        if (strlen(trim($token->value)) < 5) {
            return DetectorInterface::SCORE_CRITICAL_MATCH;
        }

        if ($token->flags & Token::FLAG_COMMENT_C) {
            return DetectorInterface::SCORE_CRITICAL_MATCH;
        }

        return DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH;
    }

    /**
     * Return an array of all the magento table names
     * @return array
     */
    protected function getMagentoTables()
    {
        if (is_null($this->magentoTables)) {
            if ($this->cacheType->test(static::CACHE_KEY_MAGENTO_TABLES)) {
                $this->magentoTables = unserialize($this->cacheType->load(static::CACHE_KEY_MAGENTO_TABLES));
            } else {
                $tableNames = [];
                $connection = $this->resourceConnection->getConnection();
                $qry = $connection->query('show tables');
                while ($tableName = $qry->fetchColumn(0)) {
                    $tableNames[] = mb_strtolower($tableName);
                }

                $this->cacheType->save(serialize($tableNames), static::CACHE_KEY_MAGENTO_TABLES);
                $this->magentoTables = $tableNames;
            }
        }

        return $this->magentoTables;
    }

    /**
     * Return true if a keyword is found in the next n tokens
     * @param array $tokens
     * @param int $position
     * @param int $maxDistance
     * @param int $maxDistance
     * * * @param $keywords
     * @param bool $searchForTableNames = true
     * @return bool
     */
    protected function hasKeywordInNextTokens(
        array $tokens,
        $position,
        $maxDistance,
        $keywords = null,
        $searchForTableNames = true
    )
    {
        for ($i = $position + 1; $i < min($position + $maxDistance + 1, count($tokens)); $i++) {
            $token = $tokens[$i];

            if (($token->type == Token::TYPE_KEYWORD) && (is_null($keywords) || in_array($token->keyword, $keywords))) {
                return true;
            }

            if ($searchForTableNames && $this->getIsTableName($token)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Search for a token type in the next tokens
     * @param array $tokens
     * @param int $position
     * @param int $maxDistance
     * @param int $type
     * @param int $flag
     * @return bool
     */
    protected function hasTypeInNextTokens(
        array $tokens,
        $position,
        $maxDistance,
        $type,
        $flag = 0x00
    )
    {
        for ($i = $position + 1; $i < min($position + $maxDistance + 1, count($tokens)); $i++) {
            $token = $tokens[$i];

            if (($token->type == $type) && (!$flag || ($token->flags & $flag))) {
                return true;
            }
        }

        return false;
    }

    /**
     * Return true if a token is a table name
     * @param Token $token
     * @return bool
     */
    protected function getIsTableName(Token $token)
    {
        if (
            (($token->type != Token::TYPE_NONE) && ($token->type != Token::TYPE_SYMBOL)) ||
            !preg_match('/^[\w\_]+$/', $token->value)
        ) {
            return false;
        }

        return in_array(mb_strtolower($token->value), $this->getMagentoTables());
    }

    /**
     * Normalize a query removing whitespaces and comments
     * @param array $tokens
     * @param array $threats
     * @param array $queryTokens
     */
    protected function normalizeQuery(array $tokens, array &$threats, array &$queryTokens)
    {
        $queryTokens = [];

        $commentsScore = 0;
        $commentsValues = [];
        for ($i = 0; $i < count($tokens); $i++) {
            $token = $tokens[$i];

            if ($token->type == Token::TYPE_WHITESPACE) {
                continue;
            }

            if ($token->type == Token::TYPE_COMMENT) {
                if ($score = $this->analyzeComment($tokens, $i)) {
                    $commentsScore += $score;
                    $commentsValues[] = $token->value;
                }

                continue;
            }

            $queryTokens[] = $token;
        }

        if ($commentsScore) {
            $threat = $this->threatInterfaceFactory->create();
            $threat
                ->setDetector($this)
                ->setId(static::RESCODE_SQLI_SIMULATED)
                ->setAdditional(['comments' => $commentsValues])
                ->setReason(__('MySQL comment found'))
                ->setScore($commentsScore);

            $threats[] = $threat;
        }
    }

    /**
     * Scan query for SQL injections
     * @param array $tokens
     * @param array $options
     * @param array $threats
     */
    protected function scanQuery(array $tokens, array $options, array &$threats)
    {
        $scanStart = $options['start'];
        $scanStop = $options['end'];

        $tokensSequence = [];

        for ($i = $scanStart; $i < count($tokens) - $scanStop - 1; $i++) {
            $token = $tokens[$i];

            $tableOperations = [
                'SELECT', 'INSERT', 'UPDATE', 'DROP', 'LOAD DATA', 'TRUNCATE', 'ALTER',
                'RENAME', 'REPLACE', 'DELETE'
            ];

            $tableOperationsOptions = [
                'ALL', 'DISTINCT', 'DISTINCTROW', 'LOW_PRIORITY', 'HIGH_PRIORITY', 'STRAIGHT_JOIN', 'SQL_SMALL_RESULT',
                'SQL_BIG_RESULT', 'SQL_BUFFER_RESULT', 'SQL_CACHE', 'SQL_NO_CACHE', 'SQL_CALC_FOUND_ROWS',
                'DELAYED', 'IGNORE', 'INTO', 'FROM', 'SET', 'QUICK', 'TEMPORARY', 'CONCURRENT', 'LOCAL', 'INFILE',
                'REPLACE', 'PARTITION', 'TABLE'
            ];

            $logicOperators = ['AND', 'OR', 'XOR'];
            $setOperators = ['IN', 'NULL', 'NOT NULL', 'INSET'];

            $tokenValue = mb_strtoupper($token->value);

            if (in_array($tokenValue, $tableOperations)) {
                $tokensSequence[] = 'X';
            } else if (in_array($tokenValue, $tableOperationsOptions)) {
                $tokensSequence[] = 'S';
            } else if (in_array($tokenValue, $logicOperators)) {
                $tokensSequence[] = 'L';
            } else if (in_array($tokenValue, $setOperators)) {
                $tokensSequence[] = 'I';
            } else if ($token->type == Token::TYPE_KEYWORD) {

                if ($token->flags & Token::FLAG_KEYWORD_FUNCTION) {
                    $tokensSequence[] = 'F';
                }
            } else if ($token->type == Token::TYPE_OPERATOR) {
                if ($token->flags & Token::FLAG_OPERATOR_SQL) {
                    $tokensSequence[] = 'O';
                } else {
                    $tokensSequence[] = '=';
                }
            } else if ($this->getIsTableName($token)) {
                $tokensSequence[] = 'T';
            } else {
                $tokensSequence[] = $token->type;
            }
        }

        if (count($tokensSequence) < 3) {
            return;
        }

        echo join('', $tokensSequence)."\n";
        return;

        $tokensPattern = join('', $tokensSequence);

        $regex = [
            [
                'id' => static::RESCODE_SQLI_FRAGMENT,
                'reason' => __('SQL injection'),
                'regex' => [
                    '(6|7)O(6|7)' => DetectorInterface::SCORE_CRITICAL_MATCH, // x or y
                    '2O2' => DetectorInterface::SCORE_CRITICAL_MATCH, // ) or (
                    '(6|7)2(6|7)' => DetectorInterface::SCORE_CRITICAL_MATCH, // x = y
                    '2\\w{0,2}?2\\w{0,2}?2' => DetectorInterface::SCORE_CRITICAL_MATCH, // Too many operators
                    'QI' => DetectorInterface::SCORE_CRITICAL_MATCH, // is not null
                    'F2' => DetectorInterface::SCORE_CRITICAL_MATCH, // functions
                    'X\\w{0,8}?T' => DetectorInterface::SCORE_CRITICAL_MATCH, // operation on a table
                    '(0|6|7)O\\w{0,2}?2(0|6|7)' => DetectorInterface::SCORE_CRITICAL_MATCH, // x or y=z
                    '(0|6|7)2\\w{0,2}?O(0|6|7)' => DetectorInterface::SCORE_CRITICAL_MATCH, // x=y or z
                ],
            ], [
                'id' => static::RESCODE_SQLI_FRAGMENT,
                'reason' => __('Suspect SQL fragment'),
                'regex' => [
                    '0(2|O)0' => DetectorInterface::SCORE_SUSPICIOUS_MATCH, // a or b
                ]
            ]
        ];

        $this->detectorRegex->scanRegex($this, $regex, $tokensPattern, $threats);

        $operators = 0;
        foreach ($tokensSequence as $token) {
            if (in_array($token, ['O', 2, 7, 8, 6], true)) {
                $operators++;
            }
        }

        $ratio = ($operators / count($tokensSequence));

        $threat = $this->threatInterfaceFactory->create();
        $threat
            ->setDetector($this)
            ->setId(static::RESCODE_SQLI_SIMULATED)
            ->setAdditional(['pattern' => $tokensPattern])
            ->setReason(__('Too many MySQL operators'))
            ->setScore(intval(10 * $ratio * DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH));

        $threats[] = $threat;
    }
//
//    /**
//     * Scan MySQL statement
//     * @param Statement $statement
//     * @param array $scanOptions
//     * @param array &$threats
//     */
//    protected function scanStatement(Statement $statement, array $scanOptions, array &$threats)
//    {
//        $score = 0;
//        if ($statement instanceof SelectStatement) {
//            if (isset($scanOptions['field'])) {
//                for ($i=0; $i<count($statement->where); $i++) {
//                    $score += DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH;
//
//                    if (in_array($statement->where[$i]->expr, ['OR', 'XOR', '||']) && ($scanOptions['quoted'])) {
//                        $score += DetectorInterface::SCORE_SURE_MATCH;
//                    }
//                }
//            }
//        }
//
//        if ($score) {
//            $threat = $this->threatInterfaceFactory->create();
//            $threat
//                ->setDetector($this)
//                ->setId(static::RESCODE_SQLI_SIMULATED)
//                ->setAdditional(['simulation' => $statement->build()])
//                ->setReason(__('Potential SQL injection detected'))
//                ->setScore($score);
//
//            $threats[] = $threat;
//        }
//
//        return;
//    }

    /**
     * Run a threat simulation
     * @param string $fieldValue
     * @return ThreatInterface[]
     */
    protected function runThreatSimulation($fieldValue)
    {
        // We need to add spaces to include worst scenarios
        $queries = $this->getInjectionSimulations(' '.$fieldValue.' ');

        $queryThreats = [];
        foreach ($queries as $query => $scanOptions) {
            $queryThreats[$query] = [];

            try {
                $parser = new Parser($query, true);
            } catch (\Exception $e) {
                continue;
            }

            if (count($parser->errors) > 0) {
                continue;
            }

            if ($scanOptions['empty']) {
                $threat = $this->threatInterfaceFactory->create();
                $threat
                    ->setDetector($this)
                    ->setId(static::RESCODE_SQLI_SIMULATED)
                    ->setAdditional(['query' => $query])
                    ->setReason(__('Full SQL query injection'))
                    ->setScore(DetectorInterface::SCORE_CRITICAL_MATCH);

                $queryThreats[$query][] = $threat;
                continue;
            }

            if (count($parser->statements) > 1) {
                $threat = $this->threatInterfaceFactory->create();
                $threat
                    ->setDetector($this)
                    ->setId(static::RESCODE_SQLI_SIMULATED)
                    ->setAdditional(['simulation' => $query])
                    ->setReason(__('Stacked MySQL queries found'))
                    ->setScore(DetectorInterface::SCORE_CRITICAL_MATCH);

                $queryThreats[$query][] = $threat;
            }

            // Locate closing comment
            $lastToken = $parser->list->tokens[$parser->list->count - 2];
            if ($lastToken->type == Token::TYPE_COMMENT) {
                $threat = $this->threatInterfaceFactory->create();
                $threat
                    ->setDetector($this)
                    ->setId(static::RESCODE_SQLI_SIMULATED)
                    ->setAdditional(['simulation' => $query])
                    ->setReason(__('Query comment exclusion detected'))
                    ->setScore($scanOptions['quoted'] ?
                        DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH :
                        DetectorInterface::SCORE_SUSPICIOUS_MATCH
                    );

                $queryThreats[$query][] = $threat;
            }

            $statement = $parser->statements[0];

            // Scan comments
            for ($i=$scanOptions['start']; $i<$statement->last; $i++) {
                $token = $parser->list->tokens[$i];

                if (
                    ($token->type == Token::TYPE_COMMENT) &&
                    ($token->flags & Token::FLAG_COMMENT_C)
                ) {
                    $threat = $this->threatInterfaceFactory->create();
                    $threat
                        ->setDetector($this)
                        ->setId(static::RESCODE_SQLI_SIMULATED)
                        ->setAdditional(['simulation' => $query])
                        ->setReason(__('C comments detected'))
                        ->setScore(DetectorInterface::SCORE_CRITICAL_MATCH);

                    $queryThreats[$query][] = $threat;
                }
            }

            // Locate opening operators (e.g: or 1 or)
            for ($i=$scanOptions['start'] + 1; $i<$statement->last; $i++) {
                $token = $parser->list->tokens[$i];

                if (in_array($token->type, [Token::TYPE_WHITESPACE])) {
                    continue;
                }

                if (in_array($token->type, [Token::TYPE_OPERATOR])) {
                    $threat = $this->threatInterfaceFactory->create();
                    $threat
                        ->setDetector($this)
                        ->setId(static::RESCODE_SQLI_SIMULATED)
                        ->setAdditional(['simulation' => $query])
                        ->setReason(__('SQL operator detected'))
                        ->setScore(DetectorInterface::SCORE_CRITICAL_MATCH);

                    $queryThreats[$query][] = $threat;
                }

                break;
            }

            $this->scanStatement($statement, $scanOptions, $queryThreats[$query]);
        }

        // Find the threat group with highest score and return it
        $highestThreats = [];
        $maxScore = 0;
        foreach ($queryThreats as $query => $threats) {
            $threatTotalScore = 0;
            foreach ($threats as $threat) {
                /** @var ThreatInterface $threat */
                $threatTotalScore += $threat->getScore();
            }

            if ($threatTotalScore > $maxScore) {
                $maxScore = $threatTotalScore;
                $highestThreats = $threats;
            }
        }

        return $highestThreats;
    }

    /**
     * Run a threat simulation
     * @param string $fieldValue
     * @return ThreatInterface[]
     */
    protected function _runThreatSimulation($fieldValue)
    {
        // We need to add spaces to include worst scenarios
        $queries = $this->getInjectionSimulations(' '.$fieldValue.' ');

        $queryThreats = [];
        foreach ($queries as $query => $scanOptions) {
            $queryThreats[$query] = [];

            try {
                $lexer = new Lexer($query, false);
                $parser = new Parser($query);
            } catch (\Exception $e) {
                continue;
            }

            $queryTokens = [];
            $this->normalizeQuery($lexer->list->tokens, $queryThreats[$query], $queryTokens);
            $this->scanQuery($queryTokens, $scanOptions, $queryThreats[$query]);
        }

        // Find the threat group with highest score and return it
        $highestThreats = [];
        $maxScore = 0;
        foreach ($queryThreats as $query => $threats) {
            $threatTotalScore = 0;
            foreach ($threats as $threat) {
                /** @var ThreatInterface $threat */
                $threatTotalScore += $threat->getScore();
            }

            if ($threatTotalScore > $maxScore) {
                $maxScore = $threatTotalScore;
                $highestThreats = $threats;
            }
        }

        return $highestThreats;
    }

    /**
     * Check request
     * @param string $fieldName
     * @param string $fieldValue
     * @return ThreatInterface[]
     */
    public function scanRequest($fieldName, $fieldValue)
    {
        // Normalize to single quote
        $fieldValue = strtolower($fieldValue);
        $fieldName = strtolower($fieldName);

        $fieldValue = str_replace('"', "'", $fieldValue);

        return $this->runThreatSimulation($fieldValue);
    }
}
