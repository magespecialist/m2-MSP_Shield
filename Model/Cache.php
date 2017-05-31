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

use IDS\Caching\CacheInterface;

class Cache implements CacheInterface
{
    const CACHE_KEY = 'ids';

    /**
     * @var CacheType
     */
    private $cacheType;

    public function __construct(
        CacheType $cacheType
    ) {
        $this->cacheType = $cacheType;
    }

    /**
     * Interface method
     *
     * @param array $data the cache data
     *
     * @return void
     */
    public function setCache(array $data)
    {
        $this->cacheType->save($data, static::CACHE_KEY, [ CacheType::CACHE_TAG ], 86400);
    }

    /**
     * Interface method
     *
     * @return void
     */
    public function getCache()
    {
        $this->cacheType->load(static::CACHE_KEY);
    }
}
