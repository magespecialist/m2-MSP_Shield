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

namespace MSP\Shield\Command;

use MSP\Shield\Api\IpsInterface;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

class Test extends Command
{
    /**
     * @var IpsInterface
     */
    private $ips;

    public function __construct(
        IpsInterface $ips
    ) {
        parent::__construct();
        $this->ips = $ips;
    }

    protected function configure()
    {
        $this->setName('msp:shield:test');
        $this->setDescription('Command line tester');

        $this->addArgument('type', InputArgument::REQUIRED, __('Type (ex.: COOKIE, GET, POST)'));
        $this->addArgument('name', InputArgument::REQUIRED, __('Parameter name'));
        $this->addArgument('value', InputArgument::REQUIRED, __('Parameter value'));

        parent::configure();
    }

    /**
     * @SuppressWarnings("PHPMD.UnusedFormalParameter")
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $area = strtoupper($input->getArgument('type'));
        $paramName = $input->getArgument('name');
        $paramValue = $input->getArgument('value');

        $scanResult = $this->ips->scanRequest([$area => [$paramName => $paramValue]]);
        foreach ($scanResult->getThreats() as $threat) {
            $output->writeln($threat->getDescription());
            $output->writeln("-----------------------------------------------");
            // @codingStandardsIgnoreStart
            $output->writeln(print_r($threat->getAdditional(), true));
            // @codingStandardsIgnoreEnd
            $output->writeln("");
        }
    }
}
