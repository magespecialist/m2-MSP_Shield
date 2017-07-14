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

namespace MSP\Shield\Plugin;

use Magento\Framework\App\State;
use Magento\Framework\AppInterface;
use Magento\Framework\App\RequestInterface;
use Magento\Framework\App\Response\Http;
use Magento\Framework\ObjectManagerInterface;
use Magento\Framework\UrlInterface;
use MSP\SecuritySuiteCommon\Api\LogManagementInterface;
use MSP\Shield\Api\ShieldInterface;
use Magento\Framework\Event\ManagerInterface as EventInterface;

class AppInterfacePlugin
{
    /**
     * @var RequestInterface
     */
    private $request;

    /**
     * @var Http
     */
    private $http;

    /**
     * @var UrlInterface
     */
    private $url;

    /**
     * @var State
     */
    private $state;

    /**
     * @var ShieldInterface
     */
    private $shield;

    /**
     * @var EventInterface
     */
    private $event;

    /**
     * @var ObjectManagerInterface
     */
    private $objectManager;


    public function __construct(
        RequestInterface $request,
        Http $http,
        UrlInterface $url,
        State $state,
        ShieldInterface $shield,
        EventInterface $event,
        ObjectManagerInterface $objectManager
    ) {
        $this->request = $request;
        $this->http = $http;
        $this->url = $url;
        $this->state = $state;
        $this->shield = $shield;
        $this->event = $event;
        $this->objectManager = $objectManager;
    }

    public function aroundLaunch(AppInterface $subject, \Closure $proceed)
    {
        // We are creating a plugin for AppInterface to make sure we can perform an IDS scan early in the code.
        // A predispatch observer is not an option.
        if ($this->shield->isEnabled() && $this->shield->shouldScan($this->request)) {
            $res = $this->shield->scanRequest();

            if ($res) {
                $tags = implode(', ', $res->getTags());

                $stopAction = $this->shield->getMinImpactToStop() &&
                    $this->shield->getMinImpactToStop() <= $res->getImpact();

                $logAction = $stopAction ||
                    ($this->shield->getMinImpactToLog() &&
                        $this->shield->getMinImpactToLog() <= $res->getImpact()
                    );

                if ($logAction) {
                    $this->event->dispatch(LogManagementInterface::EVENT_ACTIVITY, [
                        'module' => 'MSP_Shield',
                        'message' => $tags . ' (impact ' . $res->getImpact() . ')',
                        'action' => $stopAction ? 'stop' : 'log',
                        'additional' => html_entity_decode(''.$res),
                    ]);
                }

                if ($stopAction) {
                    $this->state->setAreaCode('frontend');

                    // Must use object manager because a session cannot be activated before setting area
                    $this->objectManager->get('MSP\SecuritySuiteCommon\Api\SessionInterface')
                        ->setEmergencyStopMessage(__('Hack Attempt or Suspicious Activity detected'));

                    $this->http->setRedirect($this->url->getUrl('msp_security_suite/stop/index'));
                    return $this->http;
                }
            }
        }

        return $proceed();
    }
}
