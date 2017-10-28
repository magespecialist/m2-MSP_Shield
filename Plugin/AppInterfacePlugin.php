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
use MSP\SecuritySuiteCommon\Api\AlertInterface;
use MSP\SecuritySuiteCommon\Api\LockDownInterface;
use MSP\Shield\Api\ShieldInterface;

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
     * @var LockDownInterface
     */
    private $lockDown;

    /**
     * @var AlertInterface
     */
    private $alert;

    public function __construct(
        RequestInterface $request,
        State $state,
        ShieldInterface $shield,
        AlertInterface $alert,
        LockDownInterface $lockDown
    ) {
        $this->request = $request;
        $this->state = $state;
        $this->shield = $shield;
        $this->lockDown = $lockDown;
        $this->alert = $alert;
    }

    /**
     * @param AppInterface $subject
     * @param \Closure $proceed
     * @return \Magento\Framework\App\Response\Http|mixed
     * @SuppressWarnings("PHPMD.UnusedFormalParameter")
     * @SuppressWarnings("PHPMD.CyclomaticComplexity")
     */
    public function aroundLaunch(AppInterface $subject, \Closure $proceed)
    {
        // We are creating a plugin for AppInterface to make sure we can perform an IDS scan early in the code.
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
                    $this->alert->event(
                        'MSP_Shield',
                        $res->getDescription(),
                        AlertInterface::LEVEL_SECURITY_ALERT,
                        null,
                        $stopAction ? AlertInterface::ACTION_LOCKDOWN : AlertInterface::ACTION_LOG,
                        $res->getAdditionalInfo()
                    );
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
