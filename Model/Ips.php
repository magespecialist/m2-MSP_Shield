<?php
namespace MSP\Shield\Model;

use MSP\Shield\Api\DetectorInterface;
use MSP\Shield\Api\FilterInterface;
use MSP\Shield\Api\IpsInterface;
use MSP\Shield\Api\ProcessorInterface;
use MSP\Shield\Api\ScanResultInterface;
use MSP\Shield\Api\ScanResultInterfaceFactory;

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
     */
    protected function runProcessors($fieldName, &$fieldValue)
    {
        if ($fieldValue && is_string($fieldValue)) {
            $processorLoop = true;
            while ($processorLoop && is_string($fieldValue)) {
                $processorLoop = false;
                foreach ($this->processors as $processor) {
                    if ($processor->processValue($fieldName, $fieldValue)) {
                        $processorLoop = true;
                        break;
                    }
                }
            }
        }

        if ($fieldValue && is_array($fieldValue)) {
            foreach ($fieldValue as $k => &$v) {
                $this->runProcessors($fieldName, $v);
            }
        }
    }

    /**
     * Recursively run detectors on a request
     * @param $fieldName
     * @param $fieldValue
     * @param &$threats = []
     */
    protected function runDetectors($fieldName, $fieldValue, &$threats = [])
    {
        if (is_array($fieldValue)) {
            foreach ($fieldValue as $k => $v) {
                $this->runDetectors($fieldName, $v);
            }
        } else {
            if ($this->shouldScan($fieldName, $fieldValue)) {
                foreach ($this->detectors as $detector) {
                    $res = $detector->scanRequest($fieldName, $fieldValue);
                    if (count($res)) {
                        $threats = array_merge($threats, $res);
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
    protected function shouldScan($fieldName, $fieldValue)
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

                $this->runProcessors($fieldKey, $v);
                $this->runDetectors($fieldKey, $v, $threats);
            }
        }

        /** @var $scanResult ScanResultInterface */
        $scanResult = $this->scanResultInterfaceFactory->create([
            'threats' => $threats,
        ]);

        return $scanResult;
    }
}
