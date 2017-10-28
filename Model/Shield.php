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
use Magento\Framework\App\DeploymentConfig;
use Magento\Framework\App\Filesystem\DirectoryList;
use Magento\Framework\App\RequestInterface;
use Magento\Framework\Module\Dir\Reader;
use MSP\SecuritySuiteCommon\Api\LockDownInterface;
use MSP\Shield\Api\IpsInterface;
use MSP\Shield\Api\ScanResultInterface;
use MSP\Shield\Api\ShieldInterface;

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
     * @var IpsInterface
     */
    private $ips;

    /**
     * @var LockDownInterface
     */
    private $lockDown;

    /**
     * @var RequestInterface
     */
    private $request;

    /**
     * @var DeploymentConfig
     */
    private $deploymentConfig;

    public function __construct(
        ScopeConfigInterface $scopeConfig,
        Reader $reader,
        IpsInterface $ips,
        DirectoryList $directoryList,
        LockDownInterface $lockDown,
        RequestInterface $request,
        DeploymentConfig $deploymentConfig
    ) {
        $this->scopeConfig = $scopeConfig;
        $this->directoryList = $directoryList;
        $this->reader = $reader;
        $this->ips = $ips;
        $this->lockDown = $lockDown;
        $this->request = $request;
        $this->deploymentConfig = $deploymentConfig;
    }

    /**
     * Return backend path
     * @return string
     */
    private function getBackendPath()
    {
        $backendConfigData = $this->deploymentConfig->getConfigData('backend');
        return $backendConfigData['frontName'];
    }

    /**
     * Return true if $uri is a backend URI
     * @param string $uri
     * @return bool
     */
    private function isBackendUri($uri = null)
    {
        $uri = $this->getSanitizedUri($uri);
        $backendPath = $this->getBackendPath();

        // @codingStandardsIgnoreStart
        $uri = parse_url($uri, PHP_URL_PATH);
        // @codingStandardsIgnoreEnd

        return (strpos($uri, "/$backendPath/") === 0) || preg_match("|/$backendPath$|", $uri);
    }

    /**
     * Get sanitized URI
     * @param string $uri
     * @return string
     */
    private function getSanitizedUri($uri = null)
    {
        if ($uri === null) {
            $uri = $this->request->getRequestUri();
        }

        $uri = filter_var($uri, FILTER_SANITIZE_URL);
        $uri = preg_replace('|/+|', '/', $uri);
        $uri = preg_replace('|^/.+?\.php|', '', $uri);

        return $uri;
    }

    /**
     * Return true if should scan request
     * @return bool
     */
    public function shouldScan()
    {
        if ($this->isBackendUri()) {
            return false;
        }

        $whiteList = trim($this->scopeConfig->getValue(ShieldInterface::XML_PATH_URI_WHITELIST));
        $whiteList = preg_split('/[\r\n\s,]+/', $whiteList);

        if (!$this->lockDown->getStealthMode()) {
            $whiteList[] = '/msp_security_suite/stop/index/';
        }

        $requestUri = $this->getSanitizedUri();
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
    private function getFilteredRequestArg($type, $originalRequest, $whitelist)
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
     * @SuppressWarnings(PHPMD.Superglobals)
     */
    private function getFilteredRequest()
    {
        $checkCookies = !!$this->scopeConfig->getValue(ShieldInterface::XML_PATH_CHECK_COOKIES);

        $paramsWhiteList = trim(strtolower($this->scopeConfig->getValue(ShieldInterface::XML_PATH_PARAMS_WHITELIST)));
        $paramsWhiteList = preg_split('/[\r\n\s,]+/', $paramsWhiteList);

        // @codingStandardsIgnoreStart
        // Using super globals to avoid RequestInterface use
        $request = [
            'GET' => $this->getFilteredRequestArg('GET', $_GET, $paramsWhiteList),
            'POST' => $this->getFilteredRequestArg('POST', $_POST, $paramsWhiteList)
        ];

        if ($checkCookies) {
            $request['COOKIE'] = $this->getFilteredRequestArg('COOKIE', $_COOKIE, $paramsWhiteList);
        } else {
            $request['COOKIE'] = [];
        }
        // @codingStandardsIgnoreEnd

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
        return (int) $this->scopeConfig->getValue(ShieldInterface::XML_PATH_MIN_IMPACT_LOG);
    }

    /**
     * Get minimum impact level to stop action
     * @return int
     */
    public function getMinImpactToStop()
    {
        return (int) $this->scopeConfig->getValue(ShieldInterface::XML_PATH_MIN_IMPACT_STOP);
    }
}
