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
class Xss implements DetectorInterface
{
    const CODE = 'xss';
    const RESCODE_SCRIPT_INJECTION = 'xss';

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
     * Return a list of html tags
     * @return array
     * @SuppressWarnings(PHPMD.ExcessiveMethodLength)
     */
    private function getHtmlTagsList()
    {
        return [
            "!DOCTYPE",
            "a",
            "abbr",
            "address",
            "area",
            "article",
            "aside",
            "audio",
            "b",
            "base",
            "bdi",
            "bdo",
            "blockquote",
            "body",
            "br",
            "button",
            "canvas",
            "caption",
            "cite",
            "code",
            "col",
            "colgroup",
            "data",
            "datalist",
            "dd",
            "del",
            "details",
            "dfn",
            "dialog",
            "div",
            "dl",
            "dt",
            "em",
            "embed",
            "fieldset",
            "figcaption",
            "figure",
            "footer",
            "form",
            "h1",
            "h2",
            "h3",
            "h4",
            "h5",
            "h6",
            "head",
            "header",
            "hgroup",
            "hr",
            "html",
            "i",
            "iframe",
            "img",
            "input",
            "ins",
            "kbd",
            "keygen",
            "label",
            "legend",
            "li",
            "link",
            "main",
            "map",
            "mark",
            "menu",
            "menuitem",
            "meta",
            "meter",
            "nav",
            "noscript",
            "object",
            "ol",
            "optgroup",
            "option",
            "output",
            "p",
            "param",
            "pre",
            "progress",
            "q",
            "rb",
            "rp",
            "rt",
            "rtc",
            "ruby",
            "s",
            "samp",
            "script",
            "section",
            "select",
            "small",
            "source",
            "span",
            "strong",
            "style",
            "sub",
            "summary",
            "sup",
            "table",
            "tbody",
            "td",
            "template",
            "textarea",
            "tfoot",
            "th",
            "thead",
            "time",
            "title",
            "tr",
            "track",
            "u",
            "ul",
            "var",
            "video",
            "wbr",
        ];
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
        $htmlTags = $this->getHtmlTagsList();

        // Filter noise
        $value = mb_strtolower(preg_replace('/[^\w\-=<>\'"\(\)\s]+/', '', $value));
        if (!$value) {
            return;
        }

        if (preg_match_all('/<(\w+)/', $value, $matches)) {
            foreach ($matches[1] as $match) {
                if (in_array(mb_strtolower($match), $htmlTags)) {
                    $threat = $this->threatInterfaceFactory->create();

                    $threat
                        ->setDetector($this)
                        ->setId(static::RESCODE_SCRIPT_INJECTION)
                        ->setReason(__('HTML tags detected'))
                        ->setScore(DetectorInterface::SCORE_CRITICAL_MATCH);

                    $threats[] = $threat;
                }
            }
        }

        $regex = [
            [
                'id' => static::RESCODE_SCRIPT_INJECTION,
                'reason' => __('HTML injection'),
                'regex' => [
                    '>' => DetectorInterface::SCORE_SUSPICIOUS_MATCH,
                    '(\'|").{0,20}>' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    '<\\w+' => DetectorInterface::SCORE_SUSPICIOUS_MATCH, // Unknown HTML tag?
                    '<script\\s*' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    '\\/\\w*\\s*>' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    'javascript:' => DetectorInterface::SCORE_CRITICAL_MATCH,
                ]
            ], [
                'id' => static::RESCODE_SCRIPT_INJECTION,
                'reason' => __('HTML comments injection'),
                'regex' => [
                    '\\-\\->' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    '<!\\-\\-' => DetectorInterface::SCORE_CRITICAL_MATCH,
                ]
            ], [
                'id' => static::RESCODE_SCRIPT_INJECTION,
                'reason' => __('JS injection'),
                'regex' => [
                    'location\\s*\\.\\s*href' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    '\\.to(\\w{3,5})string\\s*\\(' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    'alert\\s*\\(' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    '(?:this|window|top|parent|frames|self|content)\\s*\\.\\s*(?:location|document)' =>
                        DetectorInterface::SCORE_CRITICAL_MATCH,
                    'document\\s*\\.\\s*\\w+' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    'getelementby(?:names|id|classname|tag|tagname)\\s*\\(' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    'queryselector(?:all)?\\s*\\(' => DetectorInterface::SCORE_CRITICAL_MATCH,
                ]
            ], [
                'id' => static::RESCODE_SCRIPT_INJECTION,
                'reason' => __('HTML attributes injection'),
                'regex' => [
                    '(?:\\b|\\W)on\\w+\s*=' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    '\\b'
                        .'(?:'
                            .'src(?:alt|doc|lang|set)?|'
                            .'style|'
                            .'class|'
                            .'code(?:base)?|'
                            .'href|'
                            .'name|'
                            .'action|'
                            .'target|'
                            .'formaction|'
                            .'crossorigin|'
                            .'download|'
                            .'http\\-equiv|'
                            .'placeholder|'
                            .'rel|'
                            .'poster|'
                            .'alt|'
                            .'title|'
                            .'data(?:\\-(?:\\w+))*'
                        .')\s*=' => DetectorInterface::SCORE_CRITICAL_MATCH,
                    '\\w+\\s*=' => DetectorInterface::SCORE_HIGH_PROBABILITY_MATCH,
                ]
            ]
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
