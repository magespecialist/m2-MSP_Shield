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

namespace MSP\Shield\Api;

interface ThreatInterface
{
    const XML_PATH_DEBUG = 'msp_securitysuite_shield/general/debug';

    /**
     * Get threat identification
     * @return string
     */
    public function getId();

    /**
     * Get threat score
     * @return int
     */
    public function getScore();

    /**
     * Get a list of involved detectors
     * @return \MSP\Shield\Api\DetectorInterface
     */
    public function getDetector();

    /**
     * Get reason as string
     * @return string
     */
    public function getReason();

    /**
     * Get additional information
     * @return array
     */
    public function getAdditional();

    /**
     * Get a thread description
     * @return string
     */
    public function getDescription();

    /**
     * Get debug
     * @return array
     */
    public function getDebug();

    /**
     * Set threat identification
     * @param string $value
     * @return \MSP\Shield\Api\ThreatInterface
     */
    public function setId($value);

    /**
     * Set threat score
     * @param int $value
     * @return \MSP\Shield\Api\ThreatInterface
     */
    public function setScore($value);

    /**
     * Set a list of involved detectors
     * @param \MSP\Shield\Api\DetectorInterface $value
     * @return \MSP\Shield\Api\ThreatInterface
     */
    public function setDetector(DetectorInterface $value);

    /**
     * Set reason as string
     * @param string $value
     * @return \MSP\Shield\Api\ThreatInterface
     */
    public function setReason($value);

    /**
     * Set additional information
     * @param array $value
     * @return \MSP\Shield\Api\ThreatInterface
     */
    public function setAdditional(array $value);

    /**
     * Set debug information
     * @param array $value
     * @return \MSP\Shield\Api\ThreatInterface
     */
    public function setDebug(array $value);
}
