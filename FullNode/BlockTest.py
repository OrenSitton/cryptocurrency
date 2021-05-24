"""
Author: Oren Sitton
File: BlockTest.py
Python Version: 3
Description: 
"""
import logging
from Dependencies import hexify
from Dependencies.Block import Block
import pickle

def main():
    message = "h0000140022bd00000260abd21c140000000000000000000000000000000000000000000000000000000000301b9b00000e91118569879791b004ac26ef3ac2db616f5b730610eb4e4b152169dce385524c7275986ced6b10ff1765a4a46a59cbcda71f2222ff4060f20607bb32520100153e60abd1fa0130819f300d06092a864886f70d010101050003818d0030818902818100cd3074f8fd25a61e035854a2a6a7d8542272eac398bbd6dbecea9e841f83fe061702789c28b606ead420dc6a5845b9b79e78bba4e2df403e5d42ca455981fbf07e0beeb5bd63d4ba5695dc52a9af652543577e8f4eaf8cb1da98a1dd0b6ee09882ec38c845b6a026285489ede929c617db74bc1368eb51501688b760c76b85e70203010001000a0022bd00000360abd2231400000000000000000000000000000000000000000000000000000000000a6b4400000548ec052df1e8193f2663e34b316bbb11c13cddcf1b165606323046f7faad59b4e556f2e27387dfd372eec19f9b67d5b4cac14d45c5c0879b158eecd4970100153e60abd21c0130819f300d06092a864886f70d010101050003818d0030818902818100cd3074f8fd25a61e035854a2a6a7d8542272eac398bbd6dbecea9e841f83fe061702789c28b606ead420dc6a5845b9b79e78bba4e2df403e5d42ca455981fbf07e0beeb5bd63d4ba5695dc52a9af652543577e8f4eaf8cb1da98a1dd0b6ee09882ec38c845b6a026285489ede929c617db74bc1368eb51501688b760c76b85e70203010001000a0022bd00000460abd2301400000000000000000000000000000000000000000000000000000000001152e3000004b10c317125466daf21bc426ad23c01499347ae27154f81dc89483c78af1c1d2266bbbe82d1a840038444a4bb91ed0db83a4d33ea75ca4dbccaac449bf40100153e60abd2230130819f300d06092a864886f70d010101050003818d0030818902818100cd3074f8fd25a61e035854a2a6a7d8542272eac398bbd6dbecea9e841f83fe061702789c28b606ead420dc6a5845b9b79e78bba4e2df403e5d42ca455981fbf07e0beeb5bd63d4ba5695dc52a9af652543577e8f4eaf8cb1da98a1dd0b6ee09882ec38c845b6a026285489ede929c617db74bc1368eb51501688b760c76b85e70203010001000a0022bd00000560abd23114000000000000000000000000000000000000000000000000000000000001ff15000008215a1b7118fed6e25c96bdd3d9c93c12222b08a32b8873051df07b3914f140fc11c09c11a1dc741a15451734a92b98f4eeefd691b9ac1845b5a7bff45e0100153e60abd2300130819f300d06092a864886f70d010101050003818d0030818902818100cd3074f8fd25a61e035854a2a6a7d8542272eac398bbd6dbecea9e841f83fe061702789c28b606ead420dc6a5845b9b79e78bba4e2df403e5d42ca455981fbf07e0beeb5bd63d4ba5695dc52a9af652543577e8f4eaf8cb1da98a1dd0b6ee09882ec38c845b6a026285489ede929c617db74bc1368eb51501688b760c76b85e70203010001000a0022bd00000660abd232140000000000000000000000000000000000000000000000000000000000015c43000000425985a9c8589b66745e47b069cd59393e603fc9cb0cc24cf943a15d5f9e2d540c8e1fe9e99ed2dc9fb7180436537f238dee4feb0798b6db6e966c74a60100153e60abd2310130819f300d06092a864886f70d010101050003818d0030818902818100cd3074f8fd25a61e035854a2a6a7d8542272eac398bbd6dbecea9e841f83fe061702789c28b606ead420dc6a5845b9b79e78bba4e2df403e5d42ca455981fbf07e0beeb5bd63d4ba5695dc52a9af652543577e8f4eaf8cb1da98a1dd0b6ee09882ec38c845b6a026285489ede929c617db74bc1368eb51501688b760c76b85e70203010001000a0022bd00000760abd23414000000000000000000000000000000000000000000000000000000000002ca6500000e6f55a80891f58e8c72b326851bb8a8e75a3ae5a668410f84fc8a043de2ab50daacf984067a3d81f0096a5b94149a179dfe39eb0f5f35d95e584936b0c40100153e60abd2320130819f300d06092a864886f70d010101050003818d0030818902818100cd3074f8fd25a61e035854a2a6a7d8542272eac398bbd6dbecea9e841f83fe061702789c28b606ead420dc6a5845b9b79e78bba4e2df403e5d42ca455981fbf07e0beeb5bd63d4ba5695dc52a9af652543577e8f4eaf8cb1da98a1dd0b6ee09882ec38c845b6a026285489ede929c617db74bc1368eb51501688b760c76b85e70203010001000a0022bd00000860abd24f1400000000000000000000000000000000000000000000000000000000002054eb0000077b56d693d931a984828f9ad7d34bb15238064f2d36f1060e8ea1a037dbbbb28ab5d63e1b85d17395b352f7a8963850815a3be6dd8d01cde5c33fb7a1970100153e60abd2340130819f300d06092a864886f70d010101050003818d0030818902818100cd3074f8fd25a61e035854a2a6a7d8542272eac398bbd6dbecea9e841f83fe061702789c28b606ead420dc6a5845b9b79e78bba4e2df403e5d42ca455981fbf07e0beeb5bd63d4ba5695dc52a9af652543577e8f4eaf8cb1da98a1dd0b6ee09882ec38c845b6a026285489ede929c617db74bc1368eb51501688b760c76b85e70203010001000a0022bd00000960abd25114000000000000000000000000000000000000000000000000000000000002ff6000000c8697f9fdee34adae03bff403fb3b047a9dbadc722ed514b934102f98be16bf46d4d7c2d77e93526c27cb4c35ce3c6cc111017d79fba8ca38013c5277050100153e60abd24f0130819f300d06092a864886f70d010101050003818d0030818902818100cd3074f8fd25a61e035854a2a6a7d8542272eac398bbd6dbecea9e841f83fe061702789c28b606ead420dc6a5845b9b79e78bba4e2df403e5d42ca455981fbf07e0beeb5bd63d4ba5695dc52a9af652543577e8f4eaf8cb1da98a1dd0b6ee09882ec38c845b6a026285489ede929c617db74bc1368eb51501688b760c76b85e70203010001000a0022bd00000a60abd47214000000000000000000000000000000000000000000000000000000000003bac5000007a95783fd922d5c97577bdd6d0b7ea3b928a14726e8f2f2e7b42f9319c5802b5d3e5d19fa18adbf48f76cb1c6ff04d4121995d446125873641b67a82bbd0100153e60abd46f0130819f300d06092a864886f70d010101050003818d0030818902818100cd3074f8fd25a61e035854a2a6a7d8542272eac398bbd6dbecea9e841f83fe061702789c28b606ead420dc6a5845b9b79e78bba4e2df403e5d42ca455981fbf07e0beeb5bd63d4ba5695dc52a9af652543577e8f4eaf8cb1da98a1dd0b6ee09882ec38c845b6a026285489ede929c617db74bc1368eb51501688b760c76b85e70203010001000a0022bd00000b60abd47614000000000000000000000000000000000000000000000000000000000006a228000001bf231cd8a72f4e504ff054c7851adfc0083baf144fb17623ac303b59cec552eae904f65f7ed92f7981251c27aa20de41565d5cdec46559909db56992250100153e60abd4720130819f300d06092a864886f70d010101050003818d0030818902818100cd3074f8fd25a61e035854a2a6a7d8542272eac398bbd6dbecea9e841f83fe061702789c28b606ead420dc6a5845b9b79e78bba4e2df403e5d42ca455981fbf07e0beeb5bd63d4ba5695dc52a9af652543577e8f4eaf8cb1da98a1dd0b6ee09882ec38c845b6a026285489ede929c617db74bc1368eb51501688b760c76b85e70203010001000a0022bd00000c60abd479140000000000000000000000000000000000000000000000000000000000042b40000006c496caf03242650853279bbd80dc33248a2b9ecef3058e2d1a8f2d78dbee3ac1892ca4e76d09c0ab50d7453f2dffb01073e99070824e478524c279817c0100153e60abd4760130819f300d06092a864886f70d010101050003818d0030818902818100cd3074f8fd25a61e035854a2a6a7d8542272eac398bbd6dbecea9e841f83fe061702789c28b606ead420dc6a5845b9b79e78bba4e2df403e5d42ca455981fbf07e0beeb5bd63d4ba5695dc52a9af652543577e8f4eaf8cb1da98a1dd0b6ee09882ec38c845b6a026285489ede929c617db74bc1368eb51501688b760c76b85e70203010001000a0022bd00000d60abd48a140000000000000000000000000000000000000000000000000000000000189e36000008f94f9869a16b79b4926cc47db790b9aa5dc7f33e4afad84a7fa5367cbd4dfb8addc303203e0b59518b0f935e1cc50d371e2925ed09990b8d559e0c4edb0100153e60abd4790130819f300d06092a864886f70d010101050003818d0030818902818100cd3074f8fd25a61e035854a2a6a7d8542272eac398bbd6dbecea9e841f83fe061702789c28b606ead420dc6a5845b9b79e78bba4e2df403e5d42ca455981fbf07e0beeb5bd63d4ba5695dc52a9af652543577e8f4eaf8cb1da98a1dd0b6ee09882ec38c845b6a026285489ede929c617db74bc1368eb51501688b760c76b85e70203010001000a0022bd00000e60abd48d14000000000000000000000000000000000000000000000000000000000003211700000952a073bfabc235fef7c4a1b984f94ac697e1163237f36f20268eb350210aa679540ec7e1aa448d9a6aaba0ba8b30bce3ea809a8b09a4c89dab3e3f6f260100153e60abd48a0130819f300d06092a864886f70d010101050003818d0030818902818100cd3074f8fd25a61e035854a2a6a7d8542272eac398bbd6dbecea9e841f83fe061702789c28b606ead420dc6a5845b9b79e78bba4e2df403e5d42ca455981fbf07e0beeb5bd63d4ba5695dc52a9af652543577e8f4eaf8cb1da98a1dd0b6ee09882ec38c845b6a026285489ede929c617db74bc1368eb51501688b760c76b85e70203010001000a0022bd00000f60abd48f14000000000000000000000000000000000000000000000000000000000003e04c0000026d63b84a05b480ade084ddcdc05ad94a9c48388661049727bff487d05aa91652821d2752b2dfc98e13f047a386cfa8819937c7d57166cdf107119e83830100153e60abd48d0130819f300d06092a864886f70d010101050003818d0030818902818100cd3074f8fd25a61e035854a2a6a7d8542272eac398bbd6dbecea9e841f83fe061702789c28b606ead420dc6a5845b9b79e78bba4e2df403e5d42ca455981fbf07e0beeb5bd63d4ba5695dc52a9af652543577e8f4eaf8cb1da98a1dd0b6ee09882ec38c845b6a026285489ede929c617db74bc1368eb51501688b760c76b85e70203010001000a0022bd00001060abd4901400000000000000000000000000000000000000000000000000000000000147ee0000022be850c33503abaf7fbf5f76acdd6091fc68fa0208504858b099ab4d1efc61a6a9c191205973d77af02c9f7f937899b9188dbdd21a4565f5708dbeefc50100153e60abd48f0130819f300d06092a864886f70d010101050003818d0030818902818100cd3074f8fd25a61e035854a2a6a7d8542272eac398bbd6dbecea9e841f83fe061702789c28b606ead420dc6a5845b9b79e78bba4e2df403e5d42ca455981fbf07e0beeb5bd63d4ba5695dc52a9af652543577e8f4eaf8cb1da98a1dd0b6ee09882ec38c845b6a026285489ede929c617db74bc1368eb51501688b760c76b85e70203010001000a0022bd00001160abd4a114000000000000000000000000000000000000000000000000000000000019421f00000eeec8be77c068fcddea2aea7fdfb375bf62cb29282037addb5504a357dac204a8449cb4619e18ce5aab1944964c98b5a78f4896cea4c0f3eed1c81a12e10100153e60abd4900130819f300d06092a864886f70d010101050003818d0030818902818100cd3074f8fd25a61e035854a2a6a7d8542272eac398bbd6dbecea9e841f83fe061702789c28b606ead420dc6a5845b9b79e78bba4e2df403e5d42ca455981fbf07e0beeb5bd63d4ba5695dc52a9af652543577e8f4eaf8cb1da98a1dd0b6ee09882ec38c845b6a026285489ede929c617db74bc1368eb51501688b760c76b85e70203010001000a0022bd00001260abd5b61400000000000000000000000000000000000000000000000000000000000ccccf000002c8487fe918deba122a02a3aee64a891da954fa36f464a080446de0c56da7a06d793d71933c501e1eeab44c28a94436a5d2727ea9059dfbf87dc707b12f0100153e60abd5ad0130819f300d06092a864886f70d010101050003818d0030818902818100cd3074f8fd25a61e035854a2a6a7d8542272eac398bbd6dbecea9e841f83fe061702789c28b606ead420dc6a5845b9b79e78bba4e2df403e5d42ca455981fbf07e0beeb5bd63d4ba5695dc52a9af652543577e8f4eaf8cb1da98a1dd0b6ee09882ec38c845b6a026285489ede929c617db74bc1368eb51501688b760c76b85e70203010001000a0022bd00001360abd64b1400000000000000000000000000000000000000000000000000000000000618c200000b7a150e6abe324e88c9a20e95c989bf73d6e99544976dff35c32cc7821613fc968c84cfbcdf5c4336aa259502fd89eb75bc7fd9e33f19c903e0f374e6000100153e60abd6470130819f300d06092a864886f70d010101050003818d0030818902818100cd3074f8fd25a61e035854a2a6a7d8542272eac398bbd6dbecea9e841f83fe061702789c28b606ead420dc6a5845b9b79e78bba4e2df403e5d42ca455981fbf07e0beeb5bd63d4ba5695dc52a9af652543577e8f4eaf8cb1da98a1dd0b6ee09882ec38c845b6a026285489ede929c617db74bc1368eb51501688b760c76b85e70203010001000a0022bd00001460abd64d14000000000000000000000000000000000000000000000000000000000002cd6f000002426902b123d56014fb1bc4993b8a73f0c5f0deb0c00c917227ae11d6388e402dff12f715571bad5a28b6bb23b443a67bce58a626b1961ecd07539252df0100153e60abd64b0130819f300d06092a864886f70d010101050003818d0030818902818100cd3074f8fd25a61e035854a2a6a7d8542272eac398bbd6dbecea9e841f83fe061702789c28b606ead420dc6a5845b9b79e78bba4e2df403e5d42ca455981fbf07e0beeb5bd63d4ba5695dc52a9af652543577e8f4eaf8cb1da98a1dd0b6ee09882ec38c845b6a026285489ede929c617db74bc1368eb51501688b760c76b85e70203010001000a0022bd00001560abd7091400000000000000000000000000000000000000000000000000000000001b3d5500000c0757ca7fa71e722f54392b82ffd630f3f4b0ce49234f3cb2ab1a8897de34030c84ab7710fa22cc61700494c379dac36d519e5d70f2e993cc86fa4337f70100153e60abd6f70130819f300d06092a864886f70d010101050003818d0030818902818100cd3074f8fd25a61e035854a2a6a7d8542272eac398bbd6dbecea9e841f83fe061702789c28b606ead420dc6a5845b9b79e78bba4e2df403e5d42ca455981fbf07e0beeb5bd63d4ba5695dc52a9af652543577e8f4eaf8cb1da98a1dd0b6ee09882ec38c845b6a026285489ede929c617db74bc1368eb51501688b760c76b85e70203010001000a"
    message = message[1:]
    block_count = message[:6]
    print(int(block_count, 16))
    message = message[6:]
    while message:
        length_size = 5

        size = message[:length_size]

        while size.replace('f', '') == '':
            message = message[length_size:]
            length_size *= 2
            size = message[:length_size]

        block = message[length_size: int(size, 16) + length_size]
        print(Block.from_network_format(block))

        message = message[int(size, 16) + length_size:]
    pass

if __name__ == '__main__':
    main()
