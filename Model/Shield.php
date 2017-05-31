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
use MSP\Shield\Api\ShieldInterface;

class Shield implements ShieldInterface
{
    const XML_PATH_ENABLED = 'msp_securitysuite/shield/enabled';
    const XML_PATH_MIN_IMPACT_LOG = 'msp_securitysuite/shield/min_impact_log';
    const XML_PATH_MIN_IMPACT_STOP = 'msp_securitysuite/shield/min_impact_stop';

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
     * @var Cache
     */
    private $cache;

    public function __construct(
        ScopeConfigInterface $scopeConfig,
        Reader $reader,
        Cache $cache,
        DirectoryList $directoryList
    ) {
        $this->scopeConfig = $scopeConfig;
        $this->directoryList = $directoryList;
        $this->reader = $reader;
        $this->cache = $cache;
    }

    /**
     * Scan HTTP request and return false if no hack attempt has been detected
     * @return \IDS\Report|false
     */
    public function scanRequest()
    {
        $request = [
            'REQUEST' => $_REQUEST,
        ];

        $tmpPath = $this->directoryList->getPath(DirectoryList::TMP);

        $init = \IDS\Init::init();
        $init->config['General']['tmp_path'] = $tmpPath;
        $init->config['General']['filter_type'] = 'xml';
        $init->config['General']['scan_keys'] = false;
        $init->config['exceptions'] = [
            'GET.__utmz',
            'GET.__utmc'
        ];
        $init->config['General']['filter_path'] =
            $this->reader->getModuleDir('etc', 'MSP_Shield') . '/ids_filter.xml';

        $ids = new \IDS\Monitor($init, $this->cache);
        $result = $ids->run($request);

        return $result->isEmpty() ? false : $result;
    }

    /**
     * Return true if enabled from config
     * @return bool
     */
    public function isEnabled()
    {
        return !!$this->scopeConfig->getValue(static::XML_PATH_ENABLED);
    }

    /**
     * Get minimum impact level to log event
     * @return int
     */
    public function getMinImpactToLog()
    {
        return intval($this->scopeConfig->getValue(static::XML_PATH_MIN_IMPACT_LOG));
    }

    /**
     * Get minimum impact level to stop action
     * @return int
     */
    public function getMinImpactToStop()
    {
        return intval($this->scopeConfig->getValue(static::XML_PATH_MIN_IMPACT_STOP));
    }

}
