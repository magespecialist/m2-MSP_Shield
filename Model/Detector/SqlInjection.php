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
use Magento\Framework\Json\DecoderInterface;
use Magento\Framework\Json\EncoderInterface;
use MSP\Shield\Api\DetectorInterface;
use MSP\Shield\Api\DetectorRegexInterface;
use MSP\Shield\Api\ThreatInterface;
use MSP\Shield\Model\CacheType;
use MSP\Shield\Api\ThreatInterfaceFactory;
use PhpMyAdmin\SqlParser\Context;
use PhpMyAdmin\SqlParser\Token;

/**
 * @SuppressWarnings(PHPMD.LongVariables)
 * @SuppressWarnings(PHPMD.ExcessiveClassComplexity)
 */
class SqlInjection implements DetectorInterface
{
    const CODE = 'sql_injection';
    const RESCODE_SQLI_INJECTION = 'sqli_injection';

    const CACHE_KEY_MAGENTO_TABLES = 'sqli/table_names';
    const CACHE_KEY_MYSQL_FUNCTION = 'sqli/mysql_functions';
    const CACHE_KEY_MYSQL_KEYWORDS = 'sqli/mysql_keywords';
    const CACHE_KEY_MYSQL_FIELDS = 'sqli/mysql_fields';

    private $magentoTables = null;
    private $mysqlFunctions = null;
    private $mysqlKeywords = null;
    private $mysqlFields = null;

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

    /**
     * @var EncoderInterface
     */
    private $encoder;

    /**
     * @var DecoderInterface
     */
    private $decoder;

    public function __construct(
        DetectorRegexInterface $detectorRegex,
        ThreatInterfaceFactory $threatInterfaceFactory,
        EncoderInterface $encoder,
        DecoderInterface $decoder,
        CacheType $cacheType,
        ResourceConnection $resourceConnection
    ) {
        $this->detectorRegex = $detectorRegex;
        $this->threatInterfaceFactory = $threatInterfaceFactory;
        $this->cacheType = $cacheType;
        $this->resourceConnection = $resourceConnection;
        $this->encoder = $encoder;
        $this->decoder = $decoder;
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
    private function getMagentoTables()
    {
        if ($this->magentoTables === null) {
            if ($tables = $this->cacheType->load(static::CACHE_KEY_MAGENTO_TABLES)) {
                $this->magentoTables = $this->decoder->decode($tables);
            } else {
                $tableNames = [];
                $connection = $this->resourceConnection->getConnection();
                // @codingStandardsIgnoreStart
                $qry = $connection->query('show tables');
                // @codingStandardsIgnoreEnd
                while ($tableName = $qry->fetchColumn(0)) {
                    $tableNames[mb_strtolower($tableName)] = 1;
                }

                $this->cacheType->save($this->encoder->encode($tableNames), static::CACHE_KEY_MAGENTO_TABLES);
                $this->magentoTables = $tableNames;
            }
        }

        return $this->magentoTables;
    }

    /**
     * Get a list of MySQL functions
     * @return array
     */
    private function getMysqlFunctions()
    {
        if ($this->mysqlFunctions === null) {
            if ($functions = $this->cacheType->load(static::CACHE_KEY_MYSQL_FUNCTION)) {
                $this->mysqlFunctions = $this->decoder->decode($functions);
            } else {
                $mysqlFunctions = [];

                Context::load();
                foreach (Context::$KEYWORDS as $keyword => $flag) {
                    if ($flag & Token::FLAG_KEYWORD_FUNCTION) {
                        $mysqlFunctions[mb_strtolower($keyword)] = 1;
                    }
                }

                $this->cacheType->save($this->encoder->encode($mysqlFunctions), static::CACHE_KEY_MYSQL_FUNCTION);
                $this->mysqlFunctions = $mysqlFunctions;
            }
        }

        return $this->mysqlFunctions;
    }

    /**
     * Get a list of MySQL keywords
     * @return array
     */
    private function getMysqlKeywords()
    {
        if ($this->mysqlKeywords === null) {
            if ($keywords = $this->cacheType->load(static::CACHE_KEY_MYSQL_KEYWORDS)) {
                $this->mysqlKeywords = $this->decoder->decode($keywords);
            } else {
                $mysqlKeywords = [];

                Context::load();
                foreach (Context::$KEYWORDS as $keyword => $flag) {
                    if ($flag & Token::FLAG_KEYWORD_RESERVED) {
                        $mysqlKeywords[mb_strtolower($keyword)] = 1;
                    }
                }

                $this->cacheType->save($this->encoder->encode($mysqlKeywords), static::CACHE_KEY_MYSQL_KEYWORDS);
                $this->mysqlKeywords = $mysqlKeywords;
            }
        }

        return $this->mysqlKeywords;
    }

    /**
     * Get a list of all database field names
     * @return array
     */
    private function getMagentoFieldNames()
    {
        if ($this->mysqlFields === null) {
            if ($names = $this->cacheType->load(static::CACHE_KEY_MYSQL_FIELDS)) {
                $this->mysqlFields = $this->decoder->decode($names);
            } else {
                $mysqlFields = [];

                $connection = $this->resourceConnection->getConnection();
                $tables = $this->getMagentoTables();

                $tableNames = array_keys($tables);
                foreach ($tableNames as $tableName) {
                    $fields = $connection->describeTable($tableName);
                    foreach ($fields as $field) {
                        $mysqlFields[mb_strtolower($field['COLUMN_NAME'])] = 1;
                    }
                }

                $mysqlFields = array_unique($mysqlFields);

                $this->cacheType->save($this->encoder->encode($mysqlFields), static::CACHE_KEY_MYSQL_FIELDS);
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
    private function isTableName($token)
    {
        return array_key_exists(mb_strtolower($token), $this->getMagentoTables());
    }

    /**
     * Return true if a token is a field name
     * @param string $token
     * @return bool
     */
    private function isFieldName($token)
    {
        return array_key_exists(mb_strtolower($token), $this->getMagentoFieldNames());
    }

    /**
     * Return true if a token is a mysql keyword
     * @param string $token
     * @return bool
     */
    private function isMysqlKeyword($token)
    {
        return array_key_exists(mb_strtolower($token), $this->getMysqlKeywords());
    }

    /**
     * Return true if a token is a mysql function
     * @param string $token
     * @return bool
     */
    private function isMysqlFunction($token)
    {
        return array_key_exists(mb_strtolower($token), $this->getMysqlFunctions());
    }

    /**
     * Encode query
     * @param string $query
     * @return string
     * @SuppressWarnings(PHPMD.CyclomaticComplexity)
     */
    private function encodeQuery($query)
    {
        $dbOperations = [
            'select', 'insert', 'update', 'drop', 'load data', 'truncate', 'alter',
            'rename', 'replace', 'delete', 'desc', 'describe', 'shutdown', 'show', 'backup', 'restore',
            'union',
        ];

        $tableCreate = [
            'create'
        ];

        $tableOperationsOptions = [
            'all', 'distinct', 'distinctrow', 'low_priority', 'high_priority', 'straight_join', 'sql_small_result',
            'sql_big_result', 'sql_buffer_result', 'sql_cache', 'sql_no_cache', 'sql_calc_found_rows',
            'delayed', 'ignore', 'into', 'from', 'set', 'quick', 'temporary', 'concurrent', 'local', 'infile',
            'replace', 'partition', 'table'
        ];

        $encodedQuery = [];
        $tokens = preg_split('/(\b)/', $query, -1, PREG_SPLIT_DELIM_CAPTURE | PREG_SPLIT_NO_EMPTY);
        foreach ($tokens as $token) {
            $token = mb_strtolower(trim($token));
            if (($token === '') || in_array($token, ['.'])) {
                continue;
            }

            if (in_array($token, ['+', '=', '#', ')', '(', 'x', ',', ';'])) {
                $encodedQuery[] = $token;
            } elseif (is_numeric($token)) {
                $encodedQuery[] = 'x';
            } elseif (in_array($token, $tableCreate)) {
                $encodedQuery[] = 'c';
            } elseif (in_array($token, $dbOperations)) {
                $encodedQuery[] = 's';
            } elseif (in_array($token, $tableOperationsOptions)) {
                $encodedQuery[] = 'o';
            } elseif ($this->isMysqlFunction($token)) {
                $encodedQuery[] = 'f';
            } elseif ($this->isTableName($token)) {
                $encodedQuery[] = 't';
            } elseif ($this->isFieldName($token)) {
                $encodedQuery[] = 'x';
            } elseif ($this->isMysqlKeyword($token)) {
                $encodedQuery[] = 'k';
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
     * @SuppressWarnings(PHPMD.CyclomaticComplexity)
     * @SuppressWarnings(PHPMD.NPathComplexity)
     * @SuppressWarnings(PHPMD.ExcessiveMethodLength)
     */
    private function getNormalizedQueryScenarios($originalQuery, array &$scenariosThreats)
    {
        $scenarios = [
            $originalQuery
        ];

        if (strpos($originalQuery, '"') !== false) {
            $scenarios[] = '"' . $originalQuery . '"';
            $scenarios[] = '"' . $originalQuery;
            $scenarios[] = $originalQuery . '"';
        }

        if (strpos($originalQuery, "'") !== false) {
            $scenarios[] = "'$originalQuery'";
            $scenarios[] = "'$originalQuery";
            $scenarios[] = "$originalQuery'";
        }

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
                    ->setDebug(['query' => $modifiedQuery])
                    ->setReason(__('C comments detected'))
                    ->setScore(DetectorInterface::SCORE_CRITICAL_MATCH);

                $threats[] = $threat;
            }

            if (strpos($modifiedQuery, '/*') !== false) {
                $threat = $this->threatInterfaceFactory->create();
                $threat
                    ->setDetector($this)
                    ->setId(static::RESCODE_SQLI_INJECTION)
                    ->setDebug(['query' => $modifiedQuery])
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
                    ->setDebug(['query' => $modifiedQuery])
                    ->setReason(__('Comments detected'))
                    ->setScore($sqlCommentScore);

                $threats[] = $threat;

                $modifiedQuery = preg_replace('/(\-\-|#).*$/', "", $modifiedQuery, -1);
            }

            if (preg_match('/\b0x[0-9a-f]{32,}/i', $modifiedQuery) ||
                preg_match('/\b0b(0|1){32,}/i', $modifiedQuery)
            ) {
                $threat = $this->threatInterfaceFactory->create();
                $threat
                    ->setDetector($this)
                    ->setId(static::RESCODE_SQLI_INJECTION)
                    ->setDebug(['query' => $modifiedQuery])
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
            $modifiedQuery = str_replace(
                ['<<', '>>', '&', '|', '^', '~', '+', '-', '%', '*', '/'],
                ' + ',
                $modifiedQuery
            );
            $modifiedQuery = str_ireplace(['<', '>', '=', '<=', '>=', '==', '!=', '<=>'], ' = ', $modifiedQuery);
            $modifiedQuery = str_ireplace([' is null ', ' is not null '], ' =x ', $modifiedQuery);

            $modifiedQuery = preg_replace('/(\b)(?:and|or|xor)(\b)/i', '\\1#\\2', $modifiedQuery);
            $modifiedQuery = preg_replace('/(\b)(?:is\s+(?:not\s+)?null)(\b)/i', '\\1=x\\2', $modifiedQuery);
            $modifiedQuery = preg_replace('/(\b)0x[0-9a-f]+(\b)/i', '\\1x\\2', $modifiedQuery);
            $modifiedQuery = preg_replace('/(\b)0b[01]+(\b)/i', '\\1x\\2', $modifiedQuery);
            $modifiedQuery = preg_replace('/(\b)\w?like(\b)/i', '\\1=\\2', $modifiedQuery);
            $modifiedQuery = preg_replace('/(\b)(?:true|false)(\b)/i', '\\1x\\2', $modifiedQuery);
            $modifiedQuery = preg_replace('/(\b)not(\b)/i', '\\1\\2', $modifiedQuery);

            $scenariosThreats[$modifiedQuery] = $threats;

            if ((mb_strpos($modifiedQuery, "'") === false) &&
                (mb_strpos($modifiedQuery, '"') === false) &&
                (trim($modifiedQuery) != 'x')
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
    private function evaluateEncodedQuery($encodedQuery, array &$threats)
    {
        // Remove spaces
        $encodedQuery = str_replace(' ', '', $encodedQuery);

        $regex = [
            [
                'id' => static::RESCODE_SQLI_INJECTION,
                'reason' => __('SQL operator injection'),
                'regex' => [
                    '^(?:f|x)#' => DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH,
                    '#(?:f|x)$' => DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH,
                    '(?:f|x)#(?:f|x)' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    '#(?:f|x)#' => DetectorInterface::SCORE_CRITICAL_MATCH,

                    '(?:f|x)#0' => DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH,
                    '0#(?:f|x)' => DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH,
                    '0#0' => DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH,

                    '(?:f|x)=x' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    '0=(?:f|x)' => DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH,
                    '(?:f|x)=0' => DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH,

                    '(?:0|x|f)#(?:0|x|f)=(?:0|x|f)' => DetectorInterface::SCORE_CRITICAL_MATCH, // 1 or a = b
                    '(?:0|x|f)=(?:0|x|f)#(?:0|x|f)' => DetectorInterface::SCORE_CRITICAL_MATCH, // a = 1 or b

                    'k' => DetectorInterface::SCORE_LOW_PROBABILITY_MATCH,
                ]
            ], [
                'id' => static::RESCODE_SQLI_INJECTION,
                'reason' => __('SQL operations injection'),
                'regex' => [
                    'f\\(' => DetectorInterface::SCORE_CRITICAL_MATCH, // MySQL functions with opening parenthesis

                    's(?:o|k){0,8}y' => DetectorInterface::SCORE_CRITICAL_MATCH, // insert into tablename
                    's(?:o|k)' => DetectorInterface::SCORE_CRITICAL_MATCH, // insert into tablename
                    '(?:o|k)s' => DetectorInterface::SCORE_CRITICAL_MATCH, // union select

                    '(?:o|k)t' => DetectorInterface::SCORE_CRITICAL_MATCH, // from tablename
                    'o0' => DetectorInterface::SCORE_LOW_PROBABILITY_MATCH, // from tablename

                    'st' => DetectorInterface::SCORE_CRITICAL_MATCH, // desc tablename
                    's0' => DetectorInterface::SCORE_SUSPICIOUS_MATCH, // desc tablename

                    's{1,10}o' => DetectorInterface::SCORE_SUSPICIOUS_MATCH, // select ... from
                    's(?:(?:x|0|f),)+o' => DetectorInterface::SCORE_CRITICAL_MATCH, // select a,b,c from
                    's\\+o' => DetectorInterface::SCORE_CRITICAL_MATCH, // select * from
                    'co\\w{0,8}\\(' => DetectorInterface::SCORE_CRITICAL_MATCH, // Create table
                    'so*0,' => DetectorInterface::SCORE_CRITICAL_MATCH,

                    'k{2,}' => DetectorInterface::SCORE_SUSPICIOUS_MATCH, // Order by
                    'k{2,}x0*$' => DetectorInterface::SCORE_CRITICAL_MATCH, // Order by x desc
                ],
            ], [
                'id' => static::RESCODE_SQLI_INJECTION,
                'reason' => __('Stacked query'),
                'regex' => [
                    '^;' => DetectorInterface::SCORE_SUSPICIOUS_MATCH,
                    ';(s|f)' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    '^x+;' => DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH,
                ]
            ], [
                'id' => static::RESCODE_SQLI_INJECTION,
                'reason' => __('Arguments injection'),
                'regex' => [
                    'x\,' => DetectorInterface::SCORE_LOW_PROBABILITY_MATCH,
                ]
            ]
        ];

        $this->detectorRegex->scanRegex($this, $regex, $encodedQuery, $threats);
    }

    /**
     * Check request
     * @param string $fieldName
     * @param string $fieldValue
     * @return ThreatInterface[]
     * @SuppressWarnings("PHPMD.UnusedFormalParameter")
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
            $encodedQuery = $this->encodeQuery($scenario);
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
