<?php

namespace MSP\Shield\Model;

use MSP\Shield\Api\DetectorInterface;
use MSP\Shield\Api\FilterInterface;
use MSP\Shield\Api\IpsInterface;
use MSP\Shield\Api\ProcessorInterface;
use MSP\Shield\Api\ScanResultInterface;
use MSP\Shield\Api\ScanResultInterfaceFactory;

/**
 * @SuppressWarnings(PHPMD.LongVariables)
 */
class Ips implements IpsInterface
{
    /**
     * @var DetectorInterface[]
     */
    private $detectors;

    /**
     * @var FilterInterface[]
     */
    private $filters;

    /**
     * @var ProcessorInterface[]
     */
    private $processors;

    /**
     * @var ScanResultInterfaceFactory
     */
    private $scanResultInterfaceFactory;

    public function __construct(
        ScanResultInterfaceFactory $scanResultInterfaceFactory,
        $processors = [],
        $filters = [],
        $detectors = []
    ) {
    
        $this->detectors = $detectors;
        $this->filters = $filters;
        $this->processors = $processors;
        $this->scanResultInterfaceFactory = $scanResultInterfaceFactory;
    }

    /**
     * Recursively run processors on a request
     * @param $fieldName
     * @param $fieldValue
     * @param array &$values = []
     * @SuppressWarnings(PHPMD.CyclomaticComplexity)
     */
    private function runProcessors($fieldName, $fieldValue, array &$values = [])
    {
        if ($fieldValue) {
            if (is_string($fieldValue)) {
                foreach ($this->processors as $processor) {
                    $preFieldValue = $fieldValue;
                    $values[] = $preFieldValue;
                    $res = $processor->processValue($fieldName, $fieldValue);

                    // Remove old value, so the new one can replace it
                    if ($res === ProcessorInterface::RES_REPLACE) {
                        while (($n = array_search($preFieldValue, $values)) !== false) {
                            unset($values[$n]);
                        }
                    }

                    if (is_array($fieldValue)) {
                        break;
                    }

                    if ($res === ProcessorInterface::RES_SPAWN) {
                        $values[] = $fieldValue;
                    }

                    if ($res !== ProcessorInterface::RES_NO_MATCH) {
                        $this->runProcessors($fieldName, $fieldValue, $values);
                        break;
                    }
                }
            }

            if (is_array($fieldValue)) {
                foreach ($fieldValue as &$v) {
                    $this->runProcessors($fieldName, $v, $values);
                }
            }
        }
    }

    /**
     * Recursively run detectors on a request
     * @param $fieldName
     * @param $fieldValue
     * @param array &$threats
     */
    private function runDetectors($fieldName, $fieldValue, &$threats)
    {
        if (is_array($fieldValue)) {
            foreach ($fieldValue as $v) {
                $this->runDetectors($fieldName, $v, $threats);
            }
        } else {
            if ($this->shouldScan($fieldName, $fieldValue)) {
                foreach ($this->detectors as $detector) {
                    $scanThreats = $detector->scanRequest($fieldName, $fieldValue);
                    if (!empty($scanThreats)) {
                        foreach ($scanThreats as $scanThreat) {
                            $additional = [
                                'threat' => $scanThreat->getAdditional(),
                                'field' => $fieldName,
                            ];

                            if (!empty($scanThreat->getDebug())) {
                                $additional['debug'] = [
                                    'threat' => $scanThreat->getDebug(),
                                    'value' => utf8_encode($fieldValue),
                                    'field' => $fieldName,
                                ];
                            }

                            $scanThreat->setAdditional($additional);
                        }

                        $threats = array_merge($threats, $scanThreats);
                    }
                }
            }
        }
    }

    /**
     * Recursively run filters on a request
     * @param $fieldName
     * @param $fieldValue
     * @return boolean
     */
    private function shouldScan($fieldName, $fieldValue)
    {
        foreach ($this->filters as $filter) {
            $res = $filter->runFilter($fieldName, $fieldValue);
            if ($res == FilterInterface::MUST_SCAN) {
                return true;
            }
            if ($res == FilterInterface::NO_SCAN) {
                return false;
            }
        }
        return true;
    }

    /**
     * Check request
     * @param array $request
     * @return ScanResultInterface
     */
    public function scanRequest(array $request)
    {
        $threats = [];
        foreach ($request as $area => $params) {
            foreach ($params as $k => $v) {
                $fieldKey = $area . '.' . $k;
                $possibleValues = [];
                $this->runProcessors($fieldKey, $v, $possibleValues);
                $possibleValues = array_unique($possibleValues);
                foreach ($possibleValues as $possibleValue) {
                    if (strlen($possibleValue) > 3) {
                        $this->runDetectors($fieldKey, $possibleValue, $threats);
                    }
                }
            }
        }

        /** @var $scanResult ScanResultInterface */
        $scanResult = $this->scanResultInterfaceFactory->create([
            'threats' => $threats,
        ]);
        return $scanResult;
    }
}
