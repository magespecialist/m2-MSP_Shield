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
    const RESCODE_SQLI_FULL_INJECTION = 'sqli_full';
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
                'start' => 8,
                'end' => 0,
                'quoted' => false,
                'empty' => false,
                'field' => 'mynonexistentfield',
            ],
            "select * from mynonexistenttable where mynonexistentfield='$fieldValue'" => [
                'start' => 8,
                'end' => 0,
                'quoted' => true,
                'empty' => false,
                'field' => 'mynonexistentfield',
            ],
            "select * from mynonexistenttable where mynonexistentfield='foo' $fieldValue" => [
                'start' => 9,
                'end' => 0,
                'quoted' => false,
                'empty' => false,
            ]
        ];
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
     * Analyze comment
     * @param array $tokens
     * @param int $position
     * @return int
     */
    protected function getCommentScore(array $tokens, $position)
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
                if ($i >= count($tokens) - 2) {
                    $commentsScore += DetectorInterface::SCORE_CRITICAL_MATCH;
                }

                if ($score = $this->getCommentScore($tokens, $i)) {
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
     * @param string $query
     * @param array $options
     * @param boolean $hasErrors
     * @param array $threats
     */
    protected function scanQuery(array $tokens, $query, array $options, $hasErrors, array &$threats)
    {
        $scanStart = $options['start'];
        $scanEnd = $options['end'];

        $tokensSequence = [];

        for ($i = $scanStart; $i < count($tokens) - $scanEnd - 1; $i++) {
            $token = $tokens[$i];

            $tableOperations = [
                'SELECT', 'INSERT', 'UPDATE', 'DROP', 'LOAD DATA', 'TRUNCATE', 'ALTER',
                'RENAME', 'REPLACE', 'DELETE', 'DESC', 'DESCRIBE'
            ];

            $tableOperationsOptions = [
                'ALL', 'DISTINCT', 'DISTINCTROW', 'LOW_PRIORITY', 'HIGH_PRIORITY', 'STRAIGHT_JOIN', 'SQL_SMALL_RESULT',
                'SQL_BIG_RESULT', 'SQL_BUFFER_RESULT', 'SQL_CACHE', 'SQL_NO_CACHE', 'SQL_CALC_FOUND_ROWS',
                'DELAYED', 'IGNORE', 'INTO', 'FROM', 'SET', 'QUICK', 'TEMPORARY', 'CONCURRENT', 'LOCAL', 'INFILE',
                'REPLACE', 'PARTITION', 'TABLE'
            ];

            $logicOperators = ['AND', 'OR', 'XOR'];

            $tokenValue = mb_strtoupper($token->value);

            if (in_array($tokenValue, $tableOperations)) {
                $tokensSequence[] = 'X'; // Table operations
            } else if (in_array($tokenValue, $tableOperationsOptions)) {
                $tokensSequence[] = 'S'; // Table operation options
            } else if (in_array($tokenValue, $logicOperators)) {
                $tokensSequence[] = 'L'; // Logic operators
            } else if ($token->type == Token::TYPE_KEYWORD) {
                if ($token->flags & Token::FLAG_KEYWORD_FUNCTION) {
                    $tokensSequence[] = 'F'; // MySQL function
                } else {
                    $tokensSequence[] = $token->type;
                }
            } else if ($token->type == Token::TYPE_OPERATOR) {
                if ($token->flags & Token::FLAG_OPERATOR_SQL) {
                    if (in_array($token->value, ['(', ')'])) {
                        $tokensSequence[] = $token->value;
                    } else {
                        $tokensSequence[] = 'O'; // MySQL SQL operator
                    }
                } else if ($token->flags & Token::FLAG_OPERATOR_LOGICAL) {
                    $tokensSequence[] = 'E'; // MySQL SQL operator
                } else {
                    $tokensSequence[] = $token->type;
                }
            } else if ($this->getIsTableName($token)) {
                $tokensSequence[] = 'T'; // Existing table name
            } else {
                $tokensSequence[] = $token->type;
            }
        }

        if (count($tokensSequence) < 3) {
            return;
        }

        $tokensPattern = join('', $tokensSequence);

        echo $query . ': ' . $tokensPattern."\n";

        $regex = [
            [
                'id' => static::RESCODE_SQLI_FRAGMENT,
                'reason' => __('SQL injection'),
                'regex' => [
                    '^\\w?(?:\\(|\\)|L)' => DetectorInterface::SCORE_CRITICAL_MATCH, // Opening logic operator
                    '(?:\\(|\\)|L)\\w?$' => DetectorInterface::SCORE_CRITICAL_MATCH, // Ending logic operator
                    'F\\(' => DetectorInterface::SCORE_CRITICAL_MATCH, // MySQL functions with opening parenthesis
                    'XS{0,8}T' => DetectorInterface::SCORE_CRITICAL_MATCH, // Operation on a table
                    'X(6|0|1)+ST' => DetectorInterface::SCORE_CRITICAL_MATCH, // Operation on a table (probably a select)
                    'X(6|0|1)' => DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH, // Operation on a table (probably a select)
                    'X\\(' => DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH, // E.g.: SELECT(1)
                ],
            ], [
                'id' => static::RESCODE_SQLI_FRAGMENT,
                'reason' => __('Suspect SQL fragment'),
                'regex' => [
                    'O[^O]{2,}' => DetectorInterface::SCORE_SUSPICIOUS_MATCH, // a or b
                ]
            ]
        ];

        $this->detectorRegex->scanRegex($this, $regex, $tokensPattern, $threats);

        $operators = 0;
        foreach ($tokensSequence as $token) {
            if (in_array($token, ['O', '(', ')', 'E', 'T'], true)) {
                $operators++;
            }
        }

        $ratio = ($operators / count($tokensSequence));

        $threat = $this->threatInterfaceFactory->create();
        $threat
            ->setDetector($this)
            ->setId(static::RESCODE_SQLI_SIMULATED)
            ->setAdditional(['pattern' => $tokensPattern])
            ->setReason(__('SQL operators found'))
            ->setScore(intval(10 * $ratio * DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH));

        $threats[] = $threat;
    }

    /**
     * Scan a statement
     * @param Statement $statement
     * @param array &$threats
     */
    protected function scanStatement(Statement $statement, array &$threats)
    {
        if ($statement instanceof SelectStatement) {
            if (count($statement->union)) {
                $threat = $this->threatInterfaceFactory->create();
                $threat
                    ->setDetector($this)
                    ->setId(static::RESCODE_SQLI_SIMULATED)
                    ->setAdditional(['simulation' => $statement->build()])
                    ->setReason(__('Union select detected'))
                    ->setScore(DetectorInterface::SCORE_CRITICAL_MATCH);

                $threats[] = $threat;
            }
        }
    }

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
                $parser = new Parser($query, false);
            } catch (\Exception $e) {
                continue;
            }

            $errors = count($parser->errors);

            if ($errors > 3) {
                continue;
            }

            if (!$errors && $scanOptions['empty']) { // If we reached here, we had no errors
                $threat = $this->threatInterfaceFactory->create();
                $threat
                    ->setDetector($this)
                    ->setId(static::RESCODE_SQLI_FULL_INJECTION)
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

            foreach ($parser->statements as $statement) {
                $this->scanStatement($statement, $queryThreats[$query]);
            }

            $normalizedTokens = [];
            $this->normalizeQuery($parser->list->tokens, $queryThreats[$query], $normalizedTokens);
            $this->scanQuery($normalizedTokens, $query, $scanOptions, $errors > 0, $queryThreats[$query]);
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
