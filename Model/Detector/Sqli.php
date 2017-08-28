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
use MSP\Shield\Api\ThreatInterfaceFactory;
use PhpMyAdmin\SqlParser\Context;
use PhpMyAdmin\SqlParser\Token;

class Sqli implements DetectorInterface
{
    const CODE = 'sqli';
    const RESCODE_SQLI_INJECTION = 'sqli_injection';

    const CACHE_KEY_MAGENTO_TABLES = 'sqli/table_names';
    const CACHE_KEY_MYSQL_FUNCTION = 'sqli/mysql_functions';

    protected $magentoTables = null;
    protected $mysqlFunctions = null;

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
     * Get a list of MySQL functions
     */
    protected function getMysqlFunctions()
    {
        if (is_null($this->mysqlFunctions)) {
            if ($this->cacheType->test(static::CACHE_KEY_MYSQL_FUNCTION)) {
                $this->mysqlFunctions = unserialize($this->cacheType->load(static::CACHE_KEY_MYSQL_FUNCTION));
            } else {
                $mysqlFunctions = [];

                Context::load();
                foreach (Context::$KEYWORDS as $keyword => $flag) {
                    if ($flag & Token::FLAG_KEYWORD_FUNCTION) {
                        $mysqlFunctions[] = strtoupper($keyword);
                    }
                }

                $this->mysqlFunctions = $mysqlFunctions;
            }
        }

        return $this->mysqlFunctions;
    }

    /**
     * Return true if a token is a table name
     * @param string $token
     * @return bool
     */
    protected function getIsTableName($token)
    {
        return in_array(mb_strtolower($token), $this->getMagentoTables());
    }

    /**
     * Encode query
     * @param $query
     * @param array $threats
     * @return array
     */
    protected function encodeQuery($query, array &$threats)
    {
        $mysqlFunctions = $this->getMysqlFunctions();

        $tableOperations = [
            'SELECT', 'INSERT', 'UPDATE', 'DROP', 'LOAD DATA', 'TRUNCATE', 'ALTER',
            'RENAME', 'REPLACE', 'DELETE', 'DESC', 'DESCRIBE'
        ];

        $tableCreate = [
            'CREATE'
        ];

        $tableOperationsOptions = [
            'ALL', 'DISTINCT', 'DISTINCTROW', 'LOW_PRIORITY', 'HIGH_PRIORITY', 'STRAIGHT_JOIN', 'SQL_SMALL_RESULT',
            'SQL_BIG_RESULT', 'SQL_BUFFER_RESULT', 'SQL_CACHE', 'SQL_NO_CACHE', 'SQL_CALC_FOUND_ROWS',
            'DELAYED', 'IGNORE', 'INTO', 'FROM', 'SET', 'QUICK', 'TEMPORARY', 'CONCURRENT', 'LOCAL', 'INFILE',
            'REPLACE', 'PARTITION', 'TABLE'
        ];

        $encodedQuery = [];
        $tokens = preg_split('/(\W)/', $query, -1, PREG_SPLIT_DELIM_CAPTURE | PREG_SPLIT_NO_EMPTY);
        foreach ($tokens as $token) {
            $token = strtoupper(trim($token));
            if (!$token || in_array($token, ['.'])) {
                continue;
            }

            if (in_array($token, ['+', '=', '#', ')', '(', 'X', ',', ';'])) {
                $encodedQuery[] = $token;
            } else if (is_numeric($token)) {
                $encodedQuery[] = '1';
            } else if (in_array($token, $tableCreate)) {
                $encodedQuery[] = 'C';
            } else if (in_array($token, $tableOperations)) {
                $encodedQuery[] = 'S';
            } else if (in_array($token, $tableOperationsOptions)) {
                $encodedQuery[] = 'F';
            } else if (in_array($token, $mysqlFunctions)) {
                $encodedQuery[] = 'F';
            } else if ($this->getIsTableName($token)) {
                $encodedQuery[] = 'T';
            } else {
                $encodedQuery[] = 0;
            }
        }

        $res = join(' ', $encodedQuery);
        $res = str_replace(' ', '', $res);

        return $res;
    }

    /**
     * Normalize a query removing whitespaces and comments
     * @param string $originalQuery
     * @param array $threats
     * @return mixed
     */
    protected function getNormalizedQueryScenarios($originalQuery, array &$threats)
    {
        $scenarios = [$originalQuery, "'$originalQuery'", '"' . $originalQuery . '"'];
        $normalizedScenarios = [];

        for ($i = 0; $i < count($scenarios); $i++) {
            // Locate strings and replace
            $modifiedQuery = $scenarios[$i];
            $modifiedQuery = preg_replace(
                '/"(?:(?:"")++|[^"\x5c]++|\x5c.])*+"|\'(?:(?:\'\')++|[^\'\x5c]++|\x5c.)*+\'/',
                " X ", // Spaces around X are required to allow a correct string isolation
                $modifiedQuery
            );

            // Remove C comments
            $modifiedQuery = preg_replace('~/\*.+?\*/~', "", $modifiedQuery, -1, $cCommentsCount);
            if ($cCommentsCount) {
                $threat = $this->threatInterfaceFactory->create();
                $threat
                    ->setDetector($this)
                    ->setId(static::RESCODE_SQLI_INJECTION)
                    ->setAdditional(['query' => $modifiedQuery])
                    ->setReason(__('C comments detected'))
                    ->setScore(DetectorInterface::SCORE_CRITICAL_MATCH);

                $threats[] = $threat;
            }

            if (strpos($modifiedQuery, '/*') !== false) {
                $threat = $this->threatInterfaceFactory->create();
                $threat
                    ->setDetector($this)
                    ->setId(static::RESCODE_SQLI_INJECTION)
                    ->setAdditional(['query' => $modifiedQuery])
                    ->setReason(__('Open C comment detected'))
                    ->setScore(DetectorInterface::SCORE_CRITICAL_MATCH);

                $threats[] = $threat;
            }

            if (preg_match('/(X.{0,10})?(?:\-\-|#).+$/', $modifiedQuery, $matches)) {

                if (count($matches) > 1) {
                    $sqlCommentScore = DetectorInterface::SCORE_CRITICAL_MATCH;
                } else {
                    $sqlCommentScore = DetectorInterface::SCORE_SUSPICIOUS_MATCH;
                }

                $threat = $this->threatInterfaceFactory->create();
                $threat
                    ->setDetector($this)
                    ->setId(static::RESCODE_SQLI_INJECTION)
                    ->setAdditional(['query' => $modifiedQuery])
                    ->setReason(__('Comments detected'))
                    ->setScore($sqlCommentScore);

                $threats[] = $threat;

                $modifiedQuery = preg_replace('/(\-\-|#).+$/', "", $modifiedQuery, -1, $otherCommentsCount);
            }

            // Remove redundant spaces
            $modifiedQuery = preg_replace('/\s+/', ' ', $modifiedQuery);

            // Normalize operators (they must be flattened to a single char before passing them to analyzer)
            // Danger: our string still contains original information
            $modifiedQuery = str_replace(['(', '[', '{'], ' ( ', $modifiedQuery);
            $modifiedQuery = str_replace([')', ']', '}'], ' ) ', $modifiedQuery);
            $modifiedQuery = str_ireplace(['&&', '||'], ' # ', $modifiedQuery);
            $modifiedQuery = str_replace(['<<', '>>', '&', '|', '^', '~', '+', '-', '%', '*', '/'], ' + ', $modifiedQuery);
            $modifiedQuery = str_ireplace(['<', '>', '=', '<=', '>=', '==', '!=', '<=>'], ' = ', $modifiedQuery);
            $modifiedQuery = str_ireplace([' is null ', ' is not null '], ' =1 ', $modifiedQuery);

            $modifiedQuery = preg_replace('/(\W)(?:and|or|xor)(\W)/i', '\\1#\\2', $modifiedQuery);
            $modifiedQuery = preg_replace('/(\W)(?:is\s+(?:not\s+)?null)(\W)/i', '\\1=1\\2', $modifiedQuery);

            if (
                (mb_strpos($modifiedQuery, "'") === false) &&
                (mb_strpos($modifiedQuery, '"') === false) &&
                (trim($modifiedQuery) != 'X')
            ) {
                $normalizedScenarios[] = $modifiedQuery;
            }
        }

        return $normalizedScenarios;
    }

    /**
     * Evaluate an encoded query threat level
     * @param $encodedQuery
     * @param array $threats
     */
    protected function evaluateEncodedQuery($encodedQuery, array &$threats)
    {
        // Remove spaces
        $encodedQuery = str_replace(' ', '', $encodedQuery);

        $regex = [
            [
                'id' => static::RESCODE_SQLI_INJECTION,
                'reason' => __('SQL operator injection'),
                'regex' => [
                    '^1#' => DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH,
                    '#1$' => DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH,
                    '^X#' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    '#X$' => DetectorInterface::SCORE_CRITICAL_MATCH,

                    '(?:1|X)#(?:1|X)' => DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH,
                    'X#X' => DetectorInterface::SCORE_CRITICAL_MATCH,

                    '(?:(?:1|0|X)#(?:1|0|X)#)+' => DetectorInterface::SCORE_CRITICAL_MATCH,

                    '1#0' => DetectorInterface::SCORE_SUSPICIOUS_MATCH,
                    'X#0' => DetectorInterface::SCORE_CRITICAL_MATCH,

                    '0#1' => DetectorInterface::SCORE_SUSPICIOUS_MATCH,
                    '0#X' => DetectorInterface::SCORE_CRITICAL_MATCH,

                    '0#0' => DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH,

                    '(?:1|X)=(?:1|X)' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    '0=(?:1|X)' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    '(?:1|X)=0' => DetectorInterface::SCORE_CRITICAL_MATCH,

                    '(?:0|1|X)#(?:0|1|X)=(?:0|1|X)' => DetectorInterface::SCORE_CRITICAL_MATCH, // 1 or a = b
                    '(?:0|1|X)=(?:0|1|X)#(?:0|1|X)' => DetectorInterface::SCORE_CRITICAL_MATCH, // a = 1 or b
                ]
            ], [
                'id' => static::RESCODE_SQLI_INJECTION,
                'reason' => __('SQL operations injection'),
                'regex' => [
                    ';S' => DetectorInterface::SCORE_CRITICAL_MATCH, // Stacked query
                    'F' => DetectorInterface::SCORE_SUSPICIOUS_MATCH, // MySQL functions without opening parenthesis
                    'F\\(' => DetectorInterface::SCORE_CRITICAL_MATCH, // MySQL functions with opening parenthesis
                    'SF{0,8}T' => DetectorInterface::SCORE_CRITICAL_MATCH, // insert into tablename
                    'FT' => DetectorInterface::SCORE_CRITICAL_MATCH, // from tablename
                    'ST' => DetectorInterface::SCORE_CRITICAL_MATCH, // desc tablename
                    'S{0,10}F' => DetectorInterface::SCORE_SUSPICIOUS_MATCH, // select ... from
                    'S(?:(?:1|X|0),)+F' => DetectorInterface::SCORE_CRITICAL_MATCH, // select a,b,c from
                    'S\\+F' => DetectorInterface::SCORE_CRITICAL_MATCH, // select * from
                    'CF\\w{0,8}\\(' => DetectorInterface::SCORE_CRITICAL_MATCH, // Create table
                ],
            ], [
                'id' => static::RESCODE_SQLI_INJECTION,
                'reason' => __('Stacked query'),
                'regex' => [
                    '^;' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    '^(?:1|X)+;' => DetectorInterface::SCORE_CRITICAL_MATCH,
                ]
            ], [
                'id' => static::RESCODE_SQLI_INJECTION,
                'reason' => __('Arguments injection'),
                'regex' => [
                    '(?:(?:1|X)\,)' => DetectorInterface::SCORE_SUSPICIOUS_MATCH,
                    '0,' => DetectorInterface::SCORE_LOW_PROBABILITY_MATCH,
                ]
            ]
        ];

        $this->detectorRegex->scanRegex($this, $regex, $encodedQuery, $threats);

        $neutralTokens = substr_count($encodedQuery, '0') + substr_count($encodedQuery, '1');
        if ($neutralTokens < strlen($encodedQuery) / 2) {
            $score = DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH;
            $score += substr_count($encodedQuery, '#') * DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH;
            $score += substr_count($encodedQuery, 'X') * DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH;
            $score += substr_count($encodedQuery, '=') * DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH;
            $score += substr_count($encodedQuery, '+') * DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH;

            $threat = $this->threatInterfaceFactory->create();
            $threat
                ->setDetector($this)
                ->setId(static::RESCODE_SQLI_INJECTION)
                ->setAdditional(['encoded' => $encodedQuery])
                ->setReason(__('Suspicious commands sequence'))
                ->setScore($score);

            $threats[] = $threat;
        }
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
        $fieldValue = mb_strtolower($fieldValue);
        $fieldValue = preg_replace('/[\t\r\n\s]+/', ' ', $fieldValue);

        $threats = [];
        $scenarios = $this->getNormalizedQueryScenarios($fieldValue, $threats);
        foreach ($scenarios as $scenario) {
            $encodedQuery = $this->encodeQuery($scenario, $threats);
            $this->evaluateEncodedQuery($encodedQuery, $threats);
        }

        return $threats;
    }
}
