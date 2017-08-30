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
    const XML_PATH_ENABLED = 'msp_securitysuite_shield/general/enabled';
    const XML_PATH_CHECK_COOKIES = 'msp_securitysuite_shield/general/check_cookies';
    const XML_PATH_MIN_IMPACT_LOG = 'msp_securitysuite_shield/general/min_impact_log';
    const XML_PATH_MIN_IMPACT_STOP = 'msp_securitysuite_shield/general/min_impact_stop';
    const XML_PATH_URI_WHITELIST = 'msp_securitysuite_shield/general/uri_whitelist';
    const XML_PATH_PARAMS_WHITELIST = 'msp_securitysuite_shield/general/params_whitelist';

    /**
     * Return true if should scan request
     * @return bool
     */
    public function shouldScan();

    /**
     * Scan HTTP request and return false if no hack attempt has been detected
     * @return ScanResultInterface
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
