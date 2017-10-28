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

use Magento\Framework\Json\DecoderInterface;
use MSP\Shield\Api\ProcessorInterface;

class Unpack implements ProcessorInterface
{
    /**
     * @var DecoderInterface
     */
    private $decoder;
    /**
     * @var array
     */
    private $skip;

    public function __construct(
        DecoderInterface $decoder,
        array $skip = []
    ) {
    
        $this->decoder = $decoder;
        $this->skip = $skip;
    }

    /**
     * Return scanning results
     * @param string $fieldName
     * @param string &$fieldValue
     * @return string
     * @SuppressWarnings("PHPMD.UnusedFormalParameter")
     * @SuppressWarnings("PHPMD.NPathComplexity")
     * @SuppressWarnings("PHPMD.CyclomaticComplexity")
     */
    public function processValue($fieldName, &$fieldValue)
    {
        if (in_array($fieldName, $this->skip)) {
            return ProcessorInterface::RES_NO_MATCH;
        }

        // Check if it is an html encoded string
        // @codingStandardsIgnoreStart
        $res = html_entity_decode($fieldValue, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        // @codingStandardsIgnoreEnd
        if ($res !== $fieldValue) {
            $fieldValue = $res;
            return ProcessorInterface::RES_REPLACE;
        }

        // Check if it is a base64 string
        if (preg_match('/^(?:[A-Za-z0-9+\/]{4})*(?:[A-Za-z0-9+\/]{2}==|[A-Za-z0-9+\/]{3}=)?$/', $fieldValue)
        ) {
            // @codingStandardsIgnoreStart
            if ($res = base64_decode($fieldValue)) {
                $fieldValue = $res;
                return ProcessorInterface::RES_SPAWN;
            }
            // @codingStandardsIgnoreEnd
        }

        // Check JSON format
        if ((strlen($fieldValue) > 3) &&
            ($fieldValue[0] == '{') ||
            ($fieldValue[0] == '[') ||
            ($fieldValue[0] == '"')
        ) {
            try {
                $fieldValue = $this->decoder->decode($fieldValue);
                return ProcessorInterface::RES_REPLACE;
            } catch (\Exception $e) {
            }
        }

        // Perform URL decoding
        $urlDecoded = urldecode($fieldValue);
        if ($urlDecoded !== $fieldValue) {
            $fieldValue = $urlDecoded;
            return ProcessorInterface::RES_SPAWN;
        }

        return ProcessorInterface::RES_NO_MATCH;
    }
}
