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

interface ShieldInterface
{
    /**
     * Scan HTTP request and return false if no hack attempt has been detected
     * @return \IDS\Report|false
     */
    public function scanRequest();

    /**
     * Return true if enabled from config
     * @return bool
     */
    public function isEnabled();

    /**
     * Get minimum impact level to log event
     * @return int
     */
    public function getMinImpactToLog();

    /**
     * Get minimum impact level to stop action
     * @return int
     */
    public function getMinImpactToStop();
}
