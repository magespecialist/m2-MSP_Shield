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

/**
 * @SuppressWarnings(PHPMD.LongVariables)
 */
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
    ) {
        $this->detectorRegex = $detectorRegex;
        $this->threatInterfaceFactory = $threatInterfaceFactory;
    }

    /**
     * Encode query into normalized string
     * @param string $fieldName
     * @param string $fieldValue
     * @param array $threats
     * @return string
     * @SuppressWarnings("PHPMD.UnusedFormalParameter")
     * @SuppressWarnings("PHPMD.NPathComplexity")
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
                    'gzinflate\\s*\\(' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    'gzdeflate\\s*\\(' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    'str_rot13\\s*\\(' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    'crypt\\s*\\(' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    'crc32\\s*\\(' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    '(?:raw)?url(?:encode|decode)\\s*\\(' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    '(?:chr|ord)\\s*\\(' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    'atob\\s*\\(' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    '\\(\\s*\\)' => DetectorInterface::SCORE_SUSPICIOUS_MATCH,
                ],
            ], [
                'id' => static::RESCODE_SCRIPT_INJECTION,
                'reason' => __('Code execution attempt'),
                'regex' => [
                    '\\`.+?\\`' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    'exec\\s*\\(' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    'system\\s*\\(' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    'passthru\\s*\\(' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    'popen\\s*\\(' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    'eval\\s*\\(' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    '(?:preg|ereg|eregi)_(?:replace|match|split|filter)'
                    . '(?:[\\w\\_]+)*\\s*\\(' => DetectorInterface::SCORE_CRITICAL_MATCH,
                ]
            ], [
                'id' => static::RESCODE_SCRIPT_INJECTION,
                'reason' => __('JS-fuck detected'),
                'regex' => [
                    '!\\s*!\\s*\\[\\s*\\]' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    '\\+\\s*\\[\\s*\\]' => DetectorInterface::SCORE_CRITICAL_MATCH,
                ]
            ]
        ];

        $this->detectorRegex->scanRegex($this, $regex, $fieldValue, $threats);

        $encoded = [];
        if (preg_match('/\b(?:and|or|xor|not)\b/i', $fieldValue, $matches)) {
            $encoded[] = 'L'; // Logical match
        }
        if (preg_match('/\![^=]/i', $fieldValue, $matches)) {
            $encoded[] = 'L'; // Logical match
        }
        if (preg_match('/[^\|&](?:&&|\|\|)[^\|&]/', $fieldValue, $matches)) {
            $encoded[] = 'L'; // Logical match
        }
        if (preg_match('/(?:\w|\)|\]|\/)\\s*(?:\.|\->|::)\\s*(\w|_)/i', $fieldValue, $matches)) {
            $encoded[] = 'M'; // Method call match
        }
        if (preg_match('/(?:=<>~)/i', $fieldValue, $matches)) {
            $encoded[] = 'E'; // Assignment match
        }
        if (preg_match('/(?:\+|\-|%|\||&|<<|>>|~|\^|\*)=?/i', $fieldValue, $matches)) {
            $encoded[] = 'O'; // Operation match
        }
        if (preg_match('/(?:\{|\})/i', $fieldValue, $matches)) {
            $encoded[] = 'F'; // Function match
        }
        if (preg_match('/(?:\[|\(|\)|\])/i', $fieldValue, $matches)) {
            $encoded[] = 'P'; // Parenthesis match
        }

        $encoded = array_unique($encoded);
        sort($encoded);
        $encoded = implode('', $encoded);

        return $encoded;
    }

    /**
     * Evaluate an encoded query threat level
     * @param string $encodedQuery
     * @param array $threats
     */
    private function evaluateEncodedQuery($encodedQuery, array &$threats)
    {
        if ((strlen($encodedQuery) > 2)
        ) {
            if (preg_match('/.*F.*M.*P/', $encodedQuery) ||
                preg_match('/.*F.*L.*P/', $encodedQuery) ||
                strlen($encodedQuery > 4)
            ) {
                $score = DetectorInterface::SCORE_CRITICAL_MATCH;
            } else {
                $score = DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH;
            }

            $threat = $this->threatInterfaceFactory->create();
            $threat
                ->setDetector($this)
                ->setId(static::RESCODE_SCRIPT_INJECTION)
                ->setAdditional(['encoded' => $encodedQuery])
                ->setReason(__('Code detected'))
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
