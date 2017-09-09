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

namespace MSP\Shield\Model\Processor;

use MSP\Shield\Api\ProcessorInterface;

class Charset implements ProcessorInterface
{
    /**
     * Dig field and return true if matched
     * @param string $fieldName
     * @param string &$fieldValue
     * @return boolean
     */
    public function processValue($fieldName, &$fieldValue)
    {
//        $utf8 = utf8_decode($fieldValue);
//        if ($utf8 !== $fieldValue) {
//            $fieldValue = $utf8;
//            return true;
//        }
//
//        $utf7 = mb_convert_encoding($fieldValue, 'UTF-8', 'UTF-7');
//        if ($utf7 !== $fieldValue) {
//            $fieldValue = $utf7;
//            return true;
//        }

        return false;
    }
}
