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
use Magento\Framework\Json\EncoderInterface;
use MSP\SecuritySuiteCommon\Api\LockDownInterface;
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
     * @var EncoderInterface
     */
    private $encoder;

    /**
     * @var LockDownInterface
     */
    private $lockDown;


    public function __construct(
        RequestInterface $request,
        State $state,
        ShieldInterface $shield,
        EncoderInterface $encoder,
        EventInterface $event,
        LockDownInterface $lockDown
    ) {
        $this->request = $request;
        $this->state = $state;
        $this->shield = $shield;
        $this->event = $event;
        $this->encoder = $encoder;
        $this->lockDown = $lockDown;
    }

    public function aroundLaunch(AppInterface $subject, \Closure $proceed)
    {
        // We are creating a plugin for AppInterface to make sure we can perform an IDS scan early in the code.
        // A predispatch observer is not an option.
        if ($this->shield->isEnabled() && $this->shield->shouldScan()) {
            $res = $this->shield->scanRequest();

            if ($res && ($res->getScore() > 0)) {
                $stopAction = $this->shield->getMinImpactToStop() &&
                    $this->shield->getMinImpactToStop() <= $res->getScore();

                $logAction = $stopAction ||
                    ($this->shield->getMinImpactToLog() &&
                        $this->shield->getMinImpactToLog() <= $res->getScore()
                    );

                if ($logAction) {
                    $this->event->dispatch(LogManagementInterface::EVENT_ACTIVITY, [
                        'module' => 'MSP_Shield',
                        'message' => 'Impact ' . $res->getScore(),
                        'action' => $stopAction ? 'stop' : 'log',
                        'additional' => serialize($res->getAdditionalInfo()),
                    ]);
                }

                if ($stopAction) {
                    $this->state->setAreaCode('frontend');
                    return $this->lockDown->doHttpLockdown(__('Hack Attempt or Suspicious Activity detected'));
                }
            }
        }

        return $proceed();
    }
}
