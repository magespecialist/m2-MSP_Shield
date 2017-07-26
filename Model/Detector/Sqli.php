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

use MSP\Shield\Api\DetectorInterface;
use MSP\Shield\Api\ThreatInterface;

class Sqli implements DetectorInterface
{
    /**
     * Check request
     * @param string $fieldName
     * @param string $fieldValue
     * @return ThreatInterface
     */
    public function scanRequest($fieldName, $fieldValue)
    {
        $matches = [
            // Standard SQL
            'insert\\s*(?:.+?into)?.+?\\(.+?\\)' => DetectorInterface::SURE_MATCH_SCORE,
            'delete\\s*.+?from\\s*' => 2,
            'where\s[\\s\\w\\.,-]+\\s+=' => DetectorInterface::SURE_MATCH_SCORE,

            // Authentication bypass
            'in\\s*\\(+\s*select' => DetectorInterface::SURE_MATCH_SCORE,
            '\\".*?(?:--|#|\\/\\*|\\{)' => DetectorInterface::SURE_MATCH_SCORE,
            '"[<>~]+"' => DetectorInterface::SURE_MATCH_SCORE,
        ];

        foreach ($matches as $match => $score) {
            if (preg_match('/' . $match . '/Sim', $fieldValue)) {
                return null;
            }
        }
    }
}
