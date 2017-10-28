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

namespace MSP\Shield\Model;

use MSP\Shield\Api\DetectorRegexInterface;
use MSP\Shield\Api\ThreatInterfaceFactory;

/**
 * @SuppressWarnings(PHPMD.LongVariable)
 */
class DetectorRegex implements DetectorRegexInterface
{
    /**
     * @var ThreatInterfaceFactory
     */
    private $threatInterfaceFactory;

    public function __construct(ThreatInterfaceFactory $threatInterfaceFactory)
    {
        $this->threatInterfaceFactory = $threatInterfaceFactory;
    }

    /**
     * Scan request content over different regex patterns
     * @param \MSP\Shield\Api\DetectorInterface $detector
     * @param array $regexList
     * @param string $value
     * @param array &$threats
     */
    public function scanRegex($detector, array $regexList, $value, array &$threats)
    {
        foreach ($regexList as $regexGroup) {
            $scoreSum = 0;
            $matchingRegex = [];

            foreach ($regexGroup['regex'] as $regex => $score) {
                if (preg_match_all('/' . $regex . '/Sim', $value, $matches)) {
                    $scoreSum += $score;
                    $matchingRegex[$regex] = count($matches) * $score;
                }
            }

            if ($scoreSum) {
                /** @var \MSP\Shield\Api\ThreatInterface $threat */
                $threat = $this->threatInterfaceFactory->create();
                $threat
                    ->setDetector($detector)
                    ->setId($regexGroup['id'])
                    ->setAdditional([
                        'regex' => $matchingRegex,
                    ])
                    ->setReason($regexGroup['reason'])
                    ->setScore($scoreSum);

                $threats[] = $threat;
            }
        }
    }
}
