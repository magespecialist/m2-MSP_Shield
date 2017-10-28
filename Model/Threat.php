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

use Magento\Framework\App\Config\ScopeConfigInterface;
use MSP\Shield\Api\DetectorInterface;
use MSP\Shield\Api\ThreatInterface;

/**
 * @SuppressWarnings(PHPMD.ShortVariables)
 */
class Threat implements ThreatInterface
{
    private $id = null;
    private $score = null;
    private $detector = null;
    private $reason = null;
    private $additional = null;
    private $debug = null;

    /**
     * @var ScopeConfigInterface
     */
    private $scopeConfig;

    public function __construct(ScopeConfigInterface $scopeConfig)
    {
        $this->scopeConfig = $scopeConfig;
    }

    /**
     * Get threat identification
     * @return string
     */
    public function getId()
    {
        return $this->id;
    }

    /**
     * Get threat score
     * @return int
     */
    public function getScore()
    {
        return $this->score;
    }

    /**
     * Get a list of involved detectors
     * @return DetectorInterface
     */
    public function getDetector()
    {
        return $this->detector;
    }

    /**
     * Get reason as string
     * @return string
     */
    public function getReason()
    {
        return $this->reason;
    }

    /**
     * Set threat identification
     * @param string $value
     * @return ThreatInterface
     */
    public function setId($value)
    {
        $this->id = $value;
        return $this;
    }

    /**
     * Set threat score
     * @param int $value
     * @return ThreatInterface
     */
    public function setScore($value)
    {
        $this->score = $value;
        return $this;
    }

    /**
     * Set a list of involved detectors
     * @param DetectorInterface $value
     * @return ThreatInterface
     */
    public function setDetector(DetectorInterface $value)
    {
        $this->detector = $value;
        return $this;
    }

    /**
     * Set reason as string
     * @param string $value
     * @return ThreatInterface
     */
    public function setReason($value)
    {
        $this->reason = $value;
        return $this;
    }

    /**
     * Get a thread description
     * @return string
     */
    public function getDescription()
    {
        return $this->getDetector()->getCode() .'/'
            .$this->getId() . '[' . $this->getScore() . ']: ' . $this->getReason();
    }

    /**
     * Get additional information
     * @return array
     */
    public function getAdditional()
    {
        return $this->additional;
    }

    /**
     * Set additional information
     * @param array $value
     * @return \MSP\Shield\Api\ThreatInterface
     */
    public function setAdditional(array $value)
    {
        $this->additional = $value;
        return $this;
    }

    /**
     * Get debug
     * @return array
     */
    public function getDebug()
    {
        if (!!$this->scopeConfig->getValue(ThreatInterface::XML_PATH_DEBUG)) {
            return $this->debug;
        }

        return [];
    }

    /**
     * Set debug information
     * @param array $value
     * @return \MSP\Shield\Api\ThreatInterface
     */
    public function setDebug(array $value)
    {
        if (!!$this->scopeConfig->getValue(ThreatInterface::XML_PATH_DEBUG)) {
            $this->debug = $value;
        }

        return $this;
    }
}
