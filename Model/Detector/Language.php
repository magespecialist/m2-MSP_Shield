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

use MSP\Shield\Api\DetectorInterface;
use MSP\Shield\Api\DetectorRegexInterface;
use MSP\Shield\Api\ThreatInterface;
use MSP\Shield\Api\ThreatInterfaceFactory;

class Language implements DetectorInterface
{
    const CODE = 'language';
    const RESCODE_SCRIPT_INJECTION = 'language';

    /**
     * @var DetectorRegexInterface
     */
    private $detectorRegex;
    /**
     * @var ThreatInterfaceFactory
     */
    private $threatInterfaceFactory;

    public function __construct(
        DetectorRegexInterface $detectorRegex,
        ThreatInterfaceFactory $threatInterfaceFactory
    )
    {
        $this->detectorRegex = $detectorRegex;
        $this->threatInterfaceFactory = $threatInterfaceFactory;
    }

    /**
     * Encode query into normalized string
     * @param string $fieldName
     * @param string $fieldValue
     * @param array $threats
     * @return string
     */
    public function encodeQuery($fieldName, $fieldValue, &$threats)
    {
        $regex = [
            [
                'id' => static::RESCODE_SCRIPT_INJECTION,
                'reason' => __('Code obfuscation detected'),
                'regex' => [
                    '_encode\\s*\\(' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    '_decode\\s*\\(' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    'gzinflate\\(' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    'gzdeflate\\(' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    'str_rot13\\(' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    'crypt\\(' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    'crc32\\(' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    '(?:raw)?url(?:encode|decode)\\(' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    '(?:chr|ord)\\(' => DetectorInterface::SCORE_CRITICAL_MATCH,
                ],
            ], [
                'id' => static::RESCODE_SCRIPT_INJECTION,
                'reason' => __('Code execution attempt'),
                'regex' => [
                    'eval\\s*\\(' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    '(?:preg|ereg|eregi)_(?:replace|match|split|filter)'
                    . '(?:[\\w\\_]+)*\\s*\\(' => DetectorInterface::SCORE_CRITICAL_MATCH,
                ]
            ]
        ];

        $this->detectorRegex->scanRegex($this, $regex, $fieldValue, $threats);

        $encoded = [];
        if (preg_match('/\b(?:and|or|xor)\b/i', $fieldValue)) {
            $encoded[] = 'L';
        }
        if (preg_match('/[^\|&](?:&&|\|\|)[^\|&]/', $fieldValue)) {
            $encoded[] = 'L';
        }
        if (preg_match('/[^\.:](?:\.|\->|::)[^\.:]/i', $fieldValue)) {
            $encoded[] = 'M';
        }
        if (preg_match('/[^=]=[^~=]/i', $fieldValue)) {
            $encoded[] = 'E';
        }
        if (preg_match('/(?:<|>|<=|>=|==|===|!=|==|<=>|=~)/i', $fieldValue)) {
            $encoded[] = 'C';
        }
        if (preg_match('/(?:\+|\-|%|\||&|<<|>>|~|\^|\*)=?/i', $fieldValue)) {
            $encoded[] = 'P';
        }
        if (preg_match('/(?:\{|\[|\(|\)|\]|\})/i', $fieldValue)) {
            $encoded[] = 'F';
        }

        $encoded = array_unique($encoded);
        sort($encoded);

        $encoded = implode('', $encoded);

        return $encoded;
    }

    /**
     * Evaluate an encoded query threat level
     * @param $encodedQuery
     * @param array $threats
     */
    protected function evaluateEncodedQuery($encodedQuery, array &$threats)
    {
        if (
            (strlen($encodedQuery) > 2) &&
            preg_match('/.*E.*F/', $encodedQuery)
        ) {
            $threat = $this->threatInterfaceFactory->create();
            $threat
                ->setDetector($this)
                ->setId(static::RESCODE_SCRIPT_INJECTION)
                ->setAdditional(['encoded' => $encodedQuery])
                ->setReason(__('Code detected'))
                ->setScore(DetectorInterface::SCORE_CRITICAL_MATCH);

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
        $threats = [];

        $encodedQuery = $this->encodeQuery($fieldName, $fieldValue, $threats);
        $this->evaluateEncodedQuery($encodedQuery, $threats);

        return $threats;
    }

    /**
     * Get detector codename
     * @return string
     */
    public function getCode()
    {
        return static::CODE;
    }
}
