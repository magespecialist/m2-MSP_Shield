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

namespace MSP\Shield\Model\Detector;

use Magento\Framework\App\ResourceConnection;
use MSP\Shield\Api\DetectorInterface;
use MSP\Shield\Api\DetectorRegexInterface;
use MSP\Shield\Api\ThreatInterface;
use MSP\Shield\Api\ThreatInterfaceFactory;

/**
 * @SuppressWarnings(PHPMD.LongVariables)
 */
class Filesystem implements DetectorInterface
{
    const CODE = 'filesystem';
    const RESCODE_FILESYSTEM = 'filesystem';

    /**
     * @var DetectorRegexInterface
     */
    private $detectorRegex;

    /**
     * @var ThreatInterfaceFactory
     */
    private $threatInterfaceFactory;

    /**
     * @var ResourceConnection
     */
    private $resourceConnection;

    public function __construct(
        DetectorRegexInterface $detectorRegex,
        ThreatInterfaceFactory $threatInterfaceFactory,
        ResourceConnection $resourceConnection
    ) {
        $this->detectorRegex = $detectorRegex;
        $this->threatInterfaceFactory = $threatInterfaceFactory;
        $this->resourceConnection = $resourceConnection;
    }

    /**
     * Get detector codename
     * @return string
     */
    public function getCode()
    {
        return static::CODE;
    }

    /**
     * Evaluate an value threat level
     * @param string $fieldName
     * @param $value
     * @param array $threats
     * @SuppressWarnings("PHPMD.UnusedFormalParameter")
     */
    private function evaluateQuery($fieldName, $value, array &$threats)
    {
        $value = str_replace('\\', '/', $value);

        $regex = [
            [
                'id' => static::RESCODE_FILESYSTEM,
                'reason' => __('Filesystem disclosure attempt'),
                'regex' => [
                    '\\.\\.' => DetectorInterface::SCORE_SUSPICIOUS_MATCH,
                    '\\.\\/' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    '\\/etc\\/' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    '\\/tmp\\/' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    '\\/var\\/' => DetectorInterface::SCORE_CRITICAL_MATCH,
                ],
            ],
        ];

        $this->detectorRegex->scanRegex($this, $regex, $value, $threats);
    }

    /**
     * Check request
     * @param string $fieldName
     * @param string $fieldValue
     * @return ThreatInterface[]
     */
    public function scanRequest($fieldName, $fieldValue)
    {
        $threats = [];

        $this->evaluateQuery($fieldName, $fieldValue, $threats);

        return $threats;
    }
}
