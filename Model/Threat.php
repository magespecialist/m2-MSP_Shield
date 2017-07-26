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

use MSP\Shield\Api\DetectorInterface;
use MSP\Shield\Api\ThreatInterface;

class Threat implements ThreatInterface
{
    /**
     * Get threat identification
     * @return string
     */
    public function getId()
    {
        // TODO: Implement getId() method.
    }

    /**
     * Get threat score
     * @return int
     */
    public function getScore()
    {
        // TODO: Implement getScore() method.
    }

    /**
     * Get a list of involved detectors
     * @return DetectorInterface
     */
    public function getDetector()
    {
        // TODO: Implement getDetector() method.
    }

    /**
     * Get reason as string
     * @return string
     */
    public function getReason()
    {
        // TODO: Implement getReason() method.
    }
}
