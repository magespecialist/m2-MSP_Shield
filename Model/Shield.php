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
use Magento\Framework\App\Filesystem\DirectoryList;
use Magento\Framework\Module\Dir\Reader;
use MSP\SecuritySuiteCommon\Api\UtilsInterface;
use MSP\Shield\Api\IpsInterface;
use MSP\Shield\Api\ScanResultInterface;
use MSP\Shield\Api\ShieldInterface;
use MSP\Shield\Api\ThreatInterface;

class Shield implements ShieldInterface
{
    /**
     * @var ScopeConfigInterface
     */
    private $scopeConfig;

    /**
     * @var DirectoryList
     */
    private $directoryList;

    /**
     * @var Reader
     */
    private $reader;

    /**
     * @var UtilsInterface
     */
    private $utils;

    /**
     * @var IpsInterface
     */
    private $ips;

    public function __construct(
        ScopeConfigInterface $scopeConfig,
        Reader $reader,
        IpsInterface $ips,
        DirectoryList $directoryList,
        UtilsInterface $utils
    ) {
        $this->scopeConfig = $scopeConfig;
        $this->directoryList = $directoryList;
        $this->reader = $reader;
        $this->utils = $utils;
        $this->ips = $ips;
    }

    /**
     * Return true if should scan request
     * @return bool
     */
    public function shouldScan()
    {
        if ($this->utils->isBackendUri()) {
            return false;
        }

        $whiteList = trim($this->scopeConfig->getValue(ShieldInterface::XML_PATH_URI_WHITELIST));
        $whiteList = preg_split('/[\r\n\s,]+/', $whiteList);
        $whiteList[] = '/msp_security_suite/stop/index/';

        $requestUri = $this->utils->getSanitizedUri();
        foreach ($whiteList as $uri) {
            if ($uri && (strpos($requestUri, $uri) === 0)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Get filtered request by arg type
     * @param string $type
     * @param array $originalRequest
     * @param array $whitelist
     * @return array
     */
    protected function getFilteredRequestArg($type, $originalRequest, $whitelist)
    {
        $res = [];

        foreach ($originalRequest as $k => $v) {
            if (!in_array(strtolower($type . '.' . $k), $whitelist)) {
                $res[$k] = $v;
            }
        }

        return $res;
    }

    /**
     * Get filtered request without whitelisted parameters
     * @return array|false
     */
    protected function getFilteredRequest()
    {
        $checkCookies = !!$this->scopeConfig->getValue(ShieldInterface::XML_PATH_CHECK_COOKIES);

        $paramsWhiteList = trim(strtolower($this->scopeConfig->getValue(ShieldInterface::XML_PATH_PARAMS_WHITELIST)));
        $paramsWhiteList = preg_split('/[\r\n\s,]+/', $paramsWhiteList);

        $request = [
            'GET' => $this->getFilteredRequestArg('GET', $_GET, $paramsWhiteList),
            'POST' => $this->getFilteredRequestArg('POST', $_POST, $paramsWhiteList)
        ];

        if ($checkCookies) {
            $request['COOKIE'] = $this->getFilteredRequestArg('COOKIE', $_COOKIE, $paramsWhiteList);
        } else {
            $request['COOKIE'] = [];
        }

        return count($request['GET']) || count($request['POST']) || count($request['COOKIE']) ? $request : false;
    }

    /**
     * Scan HTTP request and return false if no hack attempt has been detected
     * @return ScanResultInterface
     */
    public function scanRequest()
    {
        $request = $this->getFilteredRequest();
        if (!$request) {
            return null;
        }

        return $this->ips->scanRequest($request);
    }

    /**
     * Return true if enabled from config
     * @return bool
     */
    public function isEnabled()
    {
        return !!$this->scopeConfig->getValue(ShieldInterface::XML_PATH_ENABLED);
    }

    /**
     * Get minimum impact level to log event
     * @return int
     */
    public function getMinImpactToLog()
    {
        return intval($this->scopeConfig->getValue(ShieldInterface::XML_PATH_MIN_IMPACT_LOG));
    }

    /**
     * Get minimum impact level to stop action
     * @return int
     */
    public function getMinImpactToStop()
    {
        return intval($this->scopeConfig->getValue(ShieldInterface::XML_PATH_MIN_IMPACT_STOP));
    }

}
