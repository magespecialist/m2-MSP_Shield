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
    const CACHE_KEY_MYSQL_KEYWORDS = 'sqli/mysql_keywords';
    const CACHE_KEY_MYSQL_FIELDS = 'sqli/mysql_fields';

    protected $magentoTables = null;
    protected $mysqlFunctions = null;
    protected $mysqlKeywords = null;
    protected $mysqlFields = null;

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
     * @return array
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

                $this->cacheType->save(serialize($mysqlFunctions), static::CACHE_KEY_MYSQL_FUNCTION);
                $this->mysqlFunctions = $mysqlFunctions;
            }
        }

        return $this->mysqlFunctions;
    }

    /**
     * Get a list of MySQL keywords
     * @return array
     */
    protected function getMysqlKeywords()
    {
        if (is_null($this->mysqlKeywords)) {
            if ($this->cacheType->test(static::CACHE_KEY_MYSQL_KEYWORDS)) {
                $this->mysqlKeywords = unserialize($this->cacheType->load(static::CACHE_KEY_MYSQL_KEYWORDS));
            } else {
                $mysqlKeywords = [];

                Context::load();
                foreach (Context::$KEYWORDS as $keyword => $flag) {
                    if ($flag & Token::FLAG_KEYWORD_RESERVED) {
                        $mysqlKeywords[] = strtoupper($keyword);
                    }
                }

                $this->cacheType->save(serialize($mysqlKeywords), static::CACHE_KEY_MYSQL_KEYWORDS);
                $this->mysqlKeywords = $mysqlKeywords;
            }
        }

        return $this->mysqlKeywords;
    }

    /**
     * Get a list of all database field names
     * @return array
     */
    protected function getMagentoFieldNames()
    {
        if (is_null($this->mysqlFields)) {
            if ($this->cacheType->test(static::CACHE_KEY_MYSQL_FIELDS)) {
                $this->mysqlFields = unserialize($this->cacheType->load(static::CACHE_KEY_MYSQL_FIELDS));
            } else {
                $mysqlFields = [];

                $connection = $this->resourceConnection->getConnection();
                $tables = $this->getMagentoTables();
                foreach ($tables as $table) {
                    $fields = $connection->describeTable($table);
                    foreach ($fields as $field) {
                        $mysqlFields[] = $field['COLUMN_NAME'];
                    }
                }

                $mysqlFields = array_unique($mysqlFields);

                $this->cacheType->save(serialize($mysqlFields), static::CACHE_KEY_MYSQL_FIELDS);
                $this->mysqlFields = $mysqlFields;
            }
        }

        return $this->mysqlFields;
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
     * Return true if a token is a field name
     * @param string $token
     * @return bool
     */
    protected function getIsFieldName($token)
    {
        return in_array(mb_strtolower($token), $this->getMagentoFieldNames());
    }

    /**
     * Return true if a token is a mysql keyword
     * @param string $token
     * @return bool
     */
    protected function getIsKeyword($token)
    {
        return in_array(mb_strtoupper($token), $this->getMysqlKeywords());
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

        $dbOperations = [
            'SELECT', 'INSERT', 'UPDATE', 'DROP', 'LOAD DATA', 'TRUNCATE', 'ALTER',
            'RENAME', 'REPLACE', 'DELETE', 'DESC', 'DESCRIBE', 'SHUTDOWN', 'SHOW', 'BACKUP', 'RESTORE',
            'UNION',
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
                $encodedQuery[] = 'X';
            } else if (in_array($token, $tableCreate)) {
                $encodedQuery[] = 'C';
            } else if (in_array($token, $dbOperations)) {
                $encodedQuery[] = 'S';
            } else if (in_array($token, $tableOperationsOptions)) {
                $encodedQuery[] = 'O';
            } else if (in_array($token, $mysqlFunctions)) {
                $encodedQuery[] = 'F';
            } else if ($this->getIsTableName($token)) {
                $encodedQuery[] = 'T';
            } else if ($this->getIsFieldName($token)) {
                $encodedQuery[] = 'X';
            } else if ($this->getIsKeyword($token)) {
                $encodedQuery[] = 'K';
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
     * @param array $scenariosThreats
     * @return array
     */
    protected function getNormalizedQueryScenarios($originalQuery, array &$scenariosThreats)
    {
        $scenarios = [
            $originalQuery,
            "'$originalQuery'",
            '"' . $originalQuery . '"',
            "'$originalQuery",
            "$originalQuery''",
            '"' . $originalQuery,
            $originalQuery . '"',
        ];
        $normalizedScenarios = [];

        for ($i = 0; $i < count($scenarios); $i++) {
            $threats = [];

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

            if (preg_match('/(X.{0,10})?(?:\-\-|#).*$/', $modifiedQuery, $matches)) {
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

                $modifiedQuery = preg_replace('/(\-\-|#).*$/', "", $modifiedQuery, -1, $otherCommentsCount);
            }

            if (preg_match('/\W0x[0-9a-f]{32,}/i', $modifiedQuery) ||
                preg_match('/\W0b(0|1){32,}/i', $modifiedQuery)
            ) {
                $threat = $this->threatInterfaceFactory->create();
                $threat
                    ->setDetector($this)
                    ->setId(static::RESCODE_SQLI_INJECTION)
                    ->setAdditional(['query' => $modifiedQuery])
                    ->setReason(__('Injection payload detected'))
                    ->setScore(DetectorInterface::SCORE_CRITICAL_MATCH);

                $threats[] = $threat;
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
            $modifiedQuery = str_ireplace([' is null ', ' is not null '], ' =X ', $modifiedQuery);

            $modifiedQuery = preg_replace('/(\W)(?:and|or|xor)(\W)/i', '\\1#\\2', $modifiedQuery);
            $modifiedQuery = preg_replace('/(\W)(?:is\s+(?:not\s+)?null)(\W)/i', '\\1=X\\2', $modifiedQuery);
            $modifiedQuery = preg_replace('/(\W)0x[0-9a-f]+(\W)/i', '\\1X\\2', $modifiedQuery);
            $modifiedQuery = preg_replace('/(\W)0b[01]+(\W)/i', '\\1X\\2', $modifiedQuery);
            $modifiedQuery = preg_replace('/(\W)\w?like(\W)/i', '\\1=\\2', $modifiedQuery);
            $modifiedQuery = preg_replace('/(\W)(?:true|false)(\W)/i', '\\1X\\2', $modifiedQuery);
            $modifiedQuery = preg_replace('/(\W)not(\W)/i', '\\1\\2', $modifiedQuery);

            $scenariosThreats[$modifiedQuery] = $threats;

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
                    '^X#' => DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH,
                    '#X$' => DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH,
                    'X#X' => DetectorInterface::SCORE_CRITICAL_MATCH,

                    'X#0' => DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH,
                    '0#X' => DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH,
                    '0#0' => DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH,

                    'X=X' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    '0=X' => DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH,
                    'X=0' => DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH,

                    '(?:0|X)#(?:0|X)=(?:0|X)' => DetectorInterface::SCORE_CRITICAL_MATCH, // 1 or a = b
                    '(?:0|X)=(?:0|X)#(?:0|X)' => DetectorInterface::SCORE_CRITICAL_MATCH, // a = 1 or b

                    'K' => DetectorInterface::SCORE_LOW_PROBABILITY_MATCH,
                ]
            ], [
                'id' => static::RESCODE_SQLI_INJECTION,
                'reason' => __('SQL operations injection'),
                'regex' => [
                    'F' => DetectorInterface::SCORE_SUSPICIOUS_MATCH, // MySQL functions without opening parenthesis
                    'F\\(' => DetectorInterface::SCORE_CRITICAL_MATCH, // MySQL functions with opening parenthesis

                    'S(?:O|K){0,8}T' => DetectorInterface::SCORE_CRITICAL_MATCH, // insert into tablename
                    'S(?:O|K)' => DetectorInterface::SCORE_CRITICAL_MATCH, // insert into tablename
                    '(?:O|K)S' => DetectorInterface::SCORE_CRITICAL_MATCH, // union select

                    '(?:O|K)T' => DetectorInterface::SCORE_CRITICAL_MATCH, // from tablename
                    'O0' => DetectorInterface::SCORE_LOW_PROBABILITY_MATCH, // from tablename

                    'ST' => DetectorInterface::SCORE_CRITICAL_MATCH, // desc tablename
                    'S0' => DetectorInterface::SCORE_SUSPICIOUS_MATCH, // desc tablename

                    'S{1,10}O' => DetectorInterface::SCORE_SUSPICIOUS_MATCH, // select ... from
                    'S(?:(?:X|0),)+O' => DetectorInterface::SCORE_CRITICAL_MATCH, // select a,b,c from
                    'S\\+O' => DetectorInterface::SCORE_CRITICAL_MATCH, // select * from
                    'CO\\w{0,8}\\(' => DetectorInterface::SCORE_CRITICAL_MATCH, // Create table
                    'SO*0,' => DetectorInterface::SCORE_CRITICAL_MATCH,

                    'K{2,}' => DetectorInterface::SCORE_SUSPICIOUS_MATCH, // Order by
                    'K{2,}X0*$' => DetectorInterface::SCORE_CRITICAL_MATCH, // Order by x desc
                ],
            ], [
                'id' => static::RESCODE_SQLI_INJECTION,
                'reason' => __('Stacked query'),
                'regex' => [
                    '^;' => DetectorInterface::SCORE_SUSPICIOUS_MATCH,
                    ';(S|F)' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    '^X+;' => DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH,
                ]
            ], [
                'id' => static::RESCODE_SQLI_INJECTION,
                'reason' => __('Arguments injection'),
                'regex' => [
                    'X\,' => DetectorInterface::SCORE_SUSPICIOUS_MATCH,
                ]
            ]
        ];

        $this->detectorRegex->scanRegex($this, $regex, $encodedQuery, $threats);

//        if (strlen($encodedQuery) > 4) {
//            $neutralTokens = substr_count($encodedQuery, '0') + substr_count($encodedQuery, '1');
//            if ($neutralTokens < strlen($encodedQuery) / 2) {
//                $score = DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH;
//                $score += substr_count($encodedQuery, '#') * DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH;
//                $score += substr_count($encodedQuery, 'X') * DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH;
//                $score += substr_count($encodedQuery, '=') * DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH;
//                $score += substr_count($encodedQuery, '+') * DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH;
//
//                $threat = $this->threatInterfaceFactory->create();
//                $threat
//                    ->setDetector($this)
//                    ->setId(static::RESCODE_SQLI_INJECTION)
//                    ->setAdditional(['encoded' => $encodedQuery])
//                    ->setReason(__('Suspicious commands sequence'))
//                    ->setScore($score);
//
//                $threats[] = $threat;
//            }
//        }
    }

    /**
     * Check request
     * @param string $fieldName
     * @param string $fieldValue
     * @return ThreatInterface[]
     */
    public function scanRequest($fieldName, $fieldValue)
    {
        // Remove non UTF-8 chars
        $fieldValue = preg_replace(
            '/((?:[\x00-\x7F]|[\xC0-\xDF][\x80-\xBF]|[\xE0-\xEF][\x80-\xBF]{2}|[\xF0-\xF7][\x80-\xBF]{3})+)|./x',
            '$1',
            $fieldValue
        );

        // Normalize to single quote
        $fieldValue = mb_strtolower($fieldValue);
        $fieldValue = preg_replace('/[\t\r\n\s]+/', ' ', $fieldValue);
        $fieldValue = str_replace('`', '', $fieldValue);

        $scenariosThreats = [];
        $scenarios = $this->getNormalizedQueryScenarios($fieldValue, $scenariosThreats);
        foreach ($scenarios as $scenario) {
            $encodedQuery = $this->encodeQuery($scenario, $scenariosThreats[$scenario]);
            $this->evaluateEncodedQuery($encodedQuery, $scenariosThreats[$scenario]);
        }

        // Find the most dangerous scenario
        $maxScore = 0;
        $maxThreats = [];
        foreach ($scenariosThreats as $scenario => $threats) {
            $scenarioScore = 0;
            foreach ($threats as $threat) {
                /** @var ThreatInterface $threat */
                $scenarioScore += $threat->getScore();
            }

            if ($scenarioScore > $maxScore) {
                $maxScore = $scenarioScore;
                $maxThreats = $threats;
            }
        }

        return $maxThreats;
    }
}
