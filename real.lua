-- real.lua
--
-- The real script, and the whole tool that reads it. Six layers, in order,
-- each one written out as the file itself performs it.
--
--   layer 1  the bytes below. Slice 2 of the block the loader decompresses:
--            10494 bytes, encrypted.
--   layer 2  the cipher. Three numbers walk forward once per byte. The key is
--            three numbers the first layer measures off the machine it runs on.
--            This is the only layer that needs something from outside the file.
--   layer 3  the reader. It refuses anything not starting MYqme, stores lengths
--            with every byte inverted, folds signed numbers, tags values.
--            Out comes a function: steps, constants, nested functions.
--   layer 4  each constant is {68, blob, g}. The blob decrypts under a key made
--            from g alone, so no measuring is needed:
--                material = tostring((g * 7919 % 2147483629 + sq) % 2147483629)
--   layer 5  what comes out is often {0, slot, material}, a pointer into the
--            string table. That table is the third slice, also below. The entry
--            decrypts under "1812386200:" .. material. Out comes the name.
--   layer 6  a constant shaped {194, blob, salt, tag} is a whole function,
--            packed. Its key is a string the program computes while it runs.
--            This file tries the values the earlier layers already produced and
--            keeps only the ones whose bytes come out starting MYqme. That test
--            is the file's own: its reader makes it too.
--
-- Layers 3 to 6 need no key and no Roblox. Only layer 2 does.
--
-- Set KEY to the three numbers and run:   luau real.lua

local KEY = nil   -- example shape: { 562797805, 1581986302, 337997813 }

----------------------------------------------------------------------------
-- layer 1: the bytes
----------------------------------------------------------------------------

local SLICE2_HEX = {
    "9c52ef5c90fe0fb3d448959e88b2abe395fe41cbd8b9bd57743fd5fbb1e45d2f1ced956a2e09038f0ffd35e4146f61caacf6fc77374bc0557a053f29",
    "e8e97e4b4fe7b5399aa152aa1f4e4b71601520438410e71bdea989d520e97260f412c040c3013859a1c10449021d7b2db9a641651625ccab45492f35",
    "dc06b775924e6b89d2ebb585c8f3c732ee7bda54f85f201b89dbcddd3a283dc71bd61eea553c66e320adb60d5f22528387dd644f646721b52ea742e6",
    "e5c31a61c841c96089607eacd15e9f728906073125cfb8365dbf6bd0aabc3e171e7e7237120cc7ea0070bf4a955ef59ada9adf0339dee32f26f7f303",
    "705e3bdb0e540e05d7b28489b88366e261f770f1f94ffcf28f6ff364f16d7a1fcc613d7c1c740893962f9ac1c0876c787dce1dd1bfd73db405613e0f",
    "ea2fca90b2309c8d7c415e090c8c4316010ab962102edc1267a6aa20dd644f3fa65e9fe00b07960a090a1c43398c6ded4df657d7c205672d124c6d4f",
    "1ef052d44d4c98004c298396dfc05536ba060ac433d8099af86ff2b9076ba43c548134d77fb14c54c50e168c434c679d6903eca8ee217279da31e64d",
    "114b6e3306516effa43073c9e47f2ef6d68583abb95aaa48510a1dea5c27f1729a562131036c81038a70bbdbc8b5face892fbbae3726f857132d9533",
    "9f687e69d01169c68ac0d572adeffbea2947d539071b094e6d85d27a2f54959fc81fcce755d4e41926b2d57133aa8ee160d026441a29a9267cb771d1",
    "9c461fc7749631ff427733592a2bf80e86dfaa6b15d6f8d9adde570cbe5ec8bc3c1662e89b29a3e6080ee00121d691bdeffe61fcd709ba7a7dd51b3a",
    "0f33570b3761f5c3ab6cd6c0045d1e4ac8fda9912d36be91ade93a9f575cc80ee8caec29191e233e7eadfa9f8e64fae0b65071842477e8d03066e58b",
    "e66a3517c1542bdc25e7a6ef53e63328fde43614ff508eb7bcb2cd913a3d421fce508e7f8fe34866685ed756a2123bdf187f9df2dd88852018b8a68e",
    "4a1ec2c28d5e2311af9102d76fa87863cafb8657a74801f7eca8fa07d163ae7e0c44871bf1be6d735ae7ef3e238b256d266121e0fee522dd2eb66bd4",
    "ec0aad16924aedd33240c9dd133f08691bbab95be7f7759c1f40eea152e8248ab4fc848e7201b3f82aba79f58f21baedfc5a9e4e84c9181c1e5cc3f0",
    "31c45790f1efafc3c2a3d8c37f78904330b1c05bc1ca4238f2c4ad96355424f61ce9b4d9a5e4b5228232831c0d37147b1e7f6d9f575880e3bbe7bc6b",
    "afe4d623f1d00fc2b03152d88b9c7d295010fa2f108cbb7e2c153e37500b49aa73932cf167acca4cd9b06c9b6d17750c92fe49c87dcecac0f2c766e0",
    "71117d9d33fcf0d047eaa1481093b74a8846716cbf41014a1e6615e7405f52945bb6f90dbe4d864fc6a0b1e8768512ba282f28023651be4f8dc5f3b6",
    "7c148ac2df4d50737c338d9b960d61d8bca65d18d7177e028924aeae9902e748e14af3b9bc55394a4d0ff4b071e2cb199eecc64ddb90d25dc1814836",
    "5a131b8d444894e75fd5246fd8ba98fdfad17171da992077dee3c7c846e1b29904637f1f35522a22e1eca3888270e433392cff308410a6de66d2154a",
    "094183060c43ffabcbd43be00b4f867efd64b4eeea7f0941745161be6d4a05d4f8871163c3083b85c1c93ca8df15d6bb985b90121b553a5a65330805",
    "80caf9e660f3b0c2c2829b3f3d4a903769b88ccdb843ae5fbe645e7c007b02de33faabe03f3a066622f42093ce87993f35085a1b1f6c67196c51467c",
    "73388131357c137de1b5b9705b128dcce5b931e3f1b24285fb442f2b54d6f115be179aed411b58a7305242607f90eb87060ec8b726b15e1a0d75334e",
    "6be243cb8ac91dc4925cf338b4fdfd124d445fb147a9a88e6ef4a4a8c48c439973938b15479f9881feaa06ab02cb12b71cbde1eca068865d46414349",
    "f9f1e0958cb86511eb0d36139b468383d496b9cd3150c21c246082546af2189f9fc98661936f60c35c50f75d077ef5cc5c02e14fa74189ecceaad34e",
    "2a4ec8d837069afb688e395bec165a2c358d579cde5b6707eb36ee9bb6cc8be644ab7d706504b94b4e9681c349134c7b6f090decb2856b123322440e",
    "6318b19c54fc6fd523559542435c7b54a071dbe6f3dd62ec62606d51416cb76943e5736673de735d00958840c7bbb9bacd9c5e72b5603568777d7bb7",
    "1567d4233b3acd9968e5a106427c1f5f30394bca6ab4acd218a3bd35944fb68304447282812262169e523e6e25ea2354f811c6e9c19262c22f8314d2",
    "060e7250b2dc89ec523b60924368b95e7121612187a899b24d4a763c5f11a18f0098f76ac0825d756ac283d378d35a2bc3bc86e6c5394e91aafef737",
    "c58c74a19900ec8b4bdce42491cc41d2a87c9bf01fc7e976ac08ea79bbfcf0216995daecbf9ac866b58b180fbe53f9882edcbcb7f41bd624acc10109",
    "f924048c367f555ca827c83dc41f18fb02ff316602a655921abccefe3831463b1d58f0b061c2c03f317fd6f72c2b6140ab3878896497c7a53f80d899",
    "27afb1bfbb93e3de3cc5dc0e2463c47cf8723053738cb4a19ae4bdf977f0c2f57b8d6fab3f0235621dcf45063d4caa2ae252d5393f64fac7ecc66766",
    "bd3609f86fe5506669c023c28e174d8e6e2d4d9a46517647ba8f0368525d2f382674ebaa9475ed927e982e67127955341938163ae6bda240a301ccf5",
    "f9be2fbf061531c27eac8b2726275a96866464fcd3dfe0dffe2f1099f9b5566a6b15d9087c814def4e2b31982550e7cc7f16df28b9ce92c079bee964",
    "0a25b75c33f6645d03a2bc14185a4ea26fde413a1070e44f2ef8fc682c2252addc9814b9499576bd5b55c1f19872ca4486be2409c8f050b805f9d8d8",
    "7f2f5df4846ecefba9a758541b1dd261b81a8406c3ad06b83487a70163805d08bc7edc6c9ccc513322d7ece0b59d98fc22bf11429312abf057a80f24",
    "e441e7cc98dac79a3d252d3a10b9f2e0cfae1e9581d8516fcf21f0f4067b353014e9c9738716484c808f7ce553ab2f6b086cc7f4b19e1109b9bc2b65",
    "c6d3ab077312e1395a04d3a3a67cba5df8e13f00281ec2e1266bfc08dc655a5702f77a8c3a42c90e4e3bdb04b7ee6f6a5fd46c981436509aadcedd3b",
    "27851bdc0d54c9850e65c8a5760685d93a09c4ca751a59d309fbffe38efe98e3407af0d27cbcc02566280d0ecaf9878e6f566b149ee5c2caa578dfbb",
    "4eb030d1fee96d1824d6280f971f553f86055eeb8efcb7fc3198e3bb624b6461c89f3811a610d9ecac75697298643fbcdb6d7fe26ee0f88006d83c95",
    "886faa13d15915b27e66f811d914cfdb2ba6ff69d6abfdb5ba7b7c97d2b0b0a89a0d3fc719f1f15a3b6ecc9b1eb100825ed023f656512cd938704cf0",
    "67ab48b759ba4dee10287bff3f1b7ff891518a2786a77f42c2f383f2be9106b8768d6868a368f3944111e1fd8649575d7d13683dd1206470475559c3",
    "9d69610eaca51c0ee208bf4c3e6f9241985fc9e461ebfc760366c80cd6a2135bcbf9a6f2c1cafb0906f4bc16bc2a83242ad455c042550abcede4375a",
    "fcb3a910f4cea97b2723b75bfc480904fe318a488da4df98815369ffcdb016b131659636ef67168a47c733c545d4d28ed2da63ffcb778f848e3d5e89",
    "b765a375595c7d07cc54dfb0d60475573531a91c734d691539d376cce39ac6cb21f3a8e3dc6cb1cefe3a20350c5a08c8ed86171fb0ffdf04527c4623",
    "18fd989ccd6d8a34222e3272079874783a52a0fb9a99dffaa06bcee526e5756ed5b9181ca019cbf035aa8b2389f74c2a760e41d48ef7aa62c1721a73",
    "88e7d2f19912923b3765e759d4550ecd63a99bd56067a532f1f0fdd97d78333c52ba87d6104c6726198b17a3f34dca5fbfac6a50f1aeb84bfc457a1c",
    "343f1fe935ce8e1bf895b28f5c3281e130c495080a60bcd54b13f869139d39fbe31079df99a536d77255052dd8fbc113c3c9b291f916a7dd112d475c",
    "5598a851789bf1ea5c59c0b9bab6cc8f981c374d35f170e9d018fc264a9a46296fe3b1d78db6385c986d23146d4e75de717dd5d141487bd5b096fd4f",
    "20c46bf6a2df842b2bcaf66ae8b31588fc09a97fcdf4f6493c399d5b0a363fb11b2e324ed17cf2d6fa60b390e94d39acd7c362cd0cec6498d084b456",
    "029ad09e9b5b0a18a5702986ec9c07aebeefaa0ca2bfd85758187c515b7a8d0306cfe6a49959551ae6477fef662871a2a936ad26e72fd08d02a01056",
    "ef1d79d952842b72997bf6c98ba7b884baa229325eefcd73797dbfa9451b9d97a3ad10372a374f5c5166b390e22af24ce235a77178efaba0e177aa3d",
    "bfc8a66c24cc1115615f0d26be61411b041af981a1aec1e630822fd84f777fc7aa1286e488ce7cd8454e10db6df35a45185952f30e07d47ed680c1c8",
    "6fe941eae4e0e9f024f0bd3c8845082f8c00d2846e96519303afd427f7b4ddab596c8ae5b9ee9606652b7169106aa87d3d50cec0c3d7a26f8e7e9f9c",
    "23ac964c6d67343dab4b6e02b2a2192260c98c6cac95b08af80f2fc2b594f242ffed2dd0ed56526e39cd58dd5b003664f043a509905815443729bb43",
    "5b2535e75ef265bfe486c07e721d50fab82bdabc1e428bbf4f4a87dfb45672b072615d3b9039bd5263fa58d7b087f236e924d72f6acbdfe9fafa14f5",
    "ffe9d292b494e74b82177851dd7d9227b9ba0ea28ff9efe0e9cb1d191acfd936241ce68d7abd514e3993551c2945dfab492f138e5dba84f90372eaa0",
    "1f180e855f205567471d71d27e7357732c28e5fe48b3c30b1cf71fdf91269e02fef346300c6258dac3906876bc117dcf48103c8e910fe49f8beb09c9",
    "242bd1b18602db639eeb48847433c514ff5e4a0a052be48cade33ec73240358d89e46db55d42b1423b31527413d72a37e45ba4e6387e3f01870bcdb4",
    "e58c149a667744fe8bdaca3874ec7e5a3dc49578d8f8533df098a935d16dd75b0dfd57d879a697e2c2e822701545920f289e8f4ff0f08445cbbea39d",
    "d9684f3d84f73af9a67c912ca9115b060ba8a9b292639e3f6025e359a0d5a7d7d3d5123bef7ff6c202cb2e747ced46bf9e9cccbcf4bc8f7710d9b74a",
    "4dd24aba5ae062b429306a6abed1a6ba24f90bb0dadebd09d1e31838d98e809f2b0b867b9e7a6a74d8ae492097deef8a8d34fd309dd0615896e5e316",
    "fe1ccce2c941f659f988a151267864ae67ae60d810f04313f1f715e4f2e9aed6df5d7714d2fc044b5a1e29fca919330ee5e4e68813210278804492bc",
    "c8875153255e837ecced024f4c2f793733a58212695e6d6c0e6666938b634589c04284d0e2780e8594b682ef63e21c13b718265059f3142f1a3ae8d5",
    "910e768a0a1a2aade2925c6d2f0c3a46e95bdc23a4df7d78f12de4fbb033136e11d57ac17c36c8aa1426aabacb36d49dabe7fb536092d2b762eae736",
    "d8a33b49cde05028539e6769bc01e7044fb0a3ae7360ad63037503b6d0f579894b7b604ba7ee94a06af4b35999fb1b2e81f6a3ec269b1585345b675f",
    "4047c23e0aa3a1c174b6e182cf6f979a7b9b83f04aed65ad46a2d0d9c9094cd7921ab6bc687ec6ace99ef58a137e56970fcf0757884a89546ed78e35",
    "f03330da120d3c3ad32a3f51f53f250c005819090ce327967621ba8f9d057da0556cf79dc769174af677fe810585c7db4faa70259d733c3a8a3d7134",
    "7e670e1341bb7975a47fba035c31f6ee61c4a170c0f43dce99535e4e3dc17673121dc7ac325aa4956c629bd85cec22cceb2863aa4dd2f81a223429d8",
    "37de50a64a08fc98f45d6ae472987ad093b29ef0129e6eaeec988f7cd6fcd36ae0cea009a9ef371f5912fbc647054ad57a660424bca2f2fb7c98cd30",
    "244749591814d5a668570d0e7c40dddd8bcc404e428732a39c9b09c80dc5717687e20f864137c6727b7b598149942c4a73e8dd2379c848d3faeb3966",
    "927700a016c4fc8cde208d661758466bfda0628fc734511474af354356b96065d989b6d20782eb59931e85470438b6f8d975a54521726de3e5ed08ae",
    "12cbbc32c71d8efa7624a234991104fda85ed83f3a3d079773927756abaccc9f208bb6c39223d0311a6c61afeffbaccc11ecb349af2113dd4a870f02",
    "06e8805efbb4849c875833a913a66070cf1ce9a76d94f6e0ed1369a6df34c7e215ae17807a7979a8523b00939541871a8b219cca19f6d3be39914202",
    "7a42319fce96cca893d86c9733648f11255d72143861f4d38e3007993311865b47ccf6d4a701248897b54c8024f97d72d7ae27a78b9b86b412986cd6",
    "1fe21a558328e3d65d467ecf4aa36665421768f319495cd7d7d418ace7523f5a93333d2e0ea493a9624b133630ac433797ac7382a6ff6b0a67bb7194",
    "692e42b3f81de6c41c9cb319c3ec046d2ca3e9dad6d66bf2bc2545b3ec338faf6e39baac40ed3a3b3bd88c7b5a7ea2715826e2d6f77ddb020d6a387b",
    "3660ef2d2e04f1d139258e2aa0ab4e41db449e70cb418813081be451e77e8a5514da33a540ef14ed6846fb89e59fc535e72386b9a72209e29c6d0d50",
    "b6c9401cb08dcf3f0eb5beaf789b22613a07d49676b2814b3e59a5ae52f8c31f4af5d0b4de71e03c250c65a9acdb033e113a76319846eba41d81eb42",
    "f543373f3b1639210430e9f1367bee7ab045b36585385561291e7f271cec179fedc15d59780b9499772da1eaebe8203b326c2fa32d4c68f8e9965de9",
    "1af12430de6222818cfd66a3cc981ed0647a652aa58dcb348ba8344cb2a5f64c2d4d76f775ff45840fee7308ababc73473537e729864a7a4afc1b4cf",
    "d000d70df68337bcb4ac60e9678a0c98db2708130c214a50e64482b013ce95e43e7840ac17e7d20d1474e8a66c8e7fbb96fdc9b346710eee692dfcb5",
    "a5a9e95657336f6487c1d70b15be9e9bb44b5ef38b088b13398a04dbd0669937573c936e090b8eedc7573597216bce446a4959852e814b3c5d91aecf",
    "d9718d78cf2127445f4bfd4ee39d4570ed481220c866f493538921fbba3238cb1f7208737611030d00a1d3b2dfc4ea940670ee0a658ba099565a73ef",
    "911044f20f8b7c4a9daf5f2c437b0f113fd356cb88907db72a53698b8bec9a51df75fb10fd08cbae88d9d6963b6bd45fbe0b422af2273f9f12e3ad01",
    "14dfe915f4182c0f6764c736f864b98a3db08afd0add4732a3ae60874593ba162dcd4353b71ee6239f83e3c45f66d46cbb56c9bdcde47d8b531f599c",
    "618ffe3a9e30f6bae78db19a784134ca030e14368602f9c1f92a3895b331c2e3adad7f7d56bece9da2c720dcfcf2cba9644b95ab99d71693332e0009",
    "c6e368eb97f36080d8c4d70dd9f5a6bb3e51ccb39b466a6572a00235bd26ee773f65c6fad405a96c3d5da22a7302ed4ad2cafe6d82358c167ae9ce26",
    "0bdd8e04704e924ec0a35388c0a3caceb8fe0e50d37d8abd29a879aa685817a41d2a6d565deed74648b9ce77b6157c1752baed1dccfe8d1389c1abfe",
    "f8206898df5f429ed3a08049718c33d8f0fef7e2ae698947cf67f799425ecbd1a486cebf8235d5a7bb54542133fa7a462e298ca371d22f255abe390e",
    "bf05251327b406a4a57f0c2938f9d31f127dace08d51a775a3198eb66cbada7c89656b2314f88e417fb2c5e2477b5510a2896bc5cc4097cd6073ded6",
    "3728e792f2ef68f6ef37e46dc75a3da1c0c3d525d4883d44bf053510463c3d6289ffdb4339cfb428e793bd3a9b9bf78790e41652e4dd8dab5f729aa6",
    "0c58dbb249d646696f6e537cb6044e051bc9ab544f580d10fd831832cc560383b3bb6ce736e3dfba12c6c7471962f28dbb0630e8c3a0136325cb488a",
    "81036ac267a19ec61f1195ac4e33b664a701a2ac2a5189743094df3aa95c059125d21dd1c87f17466a595f029c2af16ed330623778e1b990d0509895",
    "931ab0756acdc424957e97b9be4b398218ce08972e938c20c2175db9a102f55324683505b7c6729d6f2ea9891d572d136dc8b5c8314f22fe78edea78",
    "3bb0b738716989d40c23e6ad332bb7101a55e52abc1e653c29886166fa191684373d39b496396c49273ca8e2ab1391643676786351a32a28c455191f",
    "135e60d5d643d9b523d83140567c2fff546caeeef38406a6211a58e26d2537304f0cb5507a4dc652791a645aad777cb6b6af30e099c67b546be2c35a",
    "ae1e98233b31f0788601cf11d0dc7368d2315bb3406ae3085700826498d73add04c50de8e139ec699d38dbc1681b8a978d1b121f7c16035c1c622dbf",
    "7875db4f0319616ce904966e496c0b1eece5483562a0e2918b87f05b3a3e22c4f60e38a93c10274166d3185fd06fad5e5bee5a24389dcdebb638080a",
    "92b9697015e341c6825d829dd4c3d4a1ddab9b974684ee181e482f774181266e59c5aa82bfe3cd2977a948eb21e56a272e6216a273f824e7d54afc73",
    "b770db6ac5625a4c56ac4c007b4af0d95388a7c22e4f0e3399a002506cc9eefe17ed630bc32e9fce3c23b032799d0e509a3d68138a0e34597f59ffb3",
    "92451ec6103bd04505ee769d5f5d87c7ce96ee6ef6f80c86a779adeb86a6ec9e48085276da8da4ba860f140b2eb266795711389833db44b8871dcd7a",
    "f2941a5a2579956f00f33e17e593e78f00574afec209d1639832bc30bb894e46a4906583e497772303651b037cb6599ae4498ea2658d44187bc9b925",
    "16bb6c53224fa714c350db506472aef8c47b7d0afcdb6beceab583c9fe6ada749eb1f649f839b8915a122c2b77ac7dd12ddde3d33f738c4d5364a3de",
    "40f573aaa9fe60278dadc2b650da448ea9e774592bb11c86537b7834c6b3488262a16c10a9dd737161a2637890d337dd1b5db8873970df045b17116a",
    "fadf205b8ebbab8b31dfa9dfdd666a582f12fab17627ce730ed194731f9f1e2e1e0b89fcf7bc91d364574e2041488ae1e141e72c1387172dc9d431b4",
    "92632e6a19f9777eb39d46e357389cfec438f3ff21b811be1c3704d43cbe061ffcaa7bd7a21325d6bdeac3ca7a4961536b9d4b928ca075f75ca09f95",
    "9092a9f53b50f78abea4383cdc243ddbd41033cbd7851e527734cbb8d0eb488893bde88db19fbcca3bf05c5c4d75356b59b8e4a88503bc73b8625c69",
    "dfcac864e7a956d656c82610362e0a126fee88fe04db804f8df7dfaa2cee500c6634343fa6b3c0471482cea29aff98c282000146d985fc1382463c08",
    "cc63e010e1e0cdfb093e1ef7c1c8f48063e88cbe37834a016f32565de0d8aad45593bbc5d1f696a69dbe87212593686e92986924ab8f4bd1dd50be6a",
    "65d621814abf570790b673c1b25d6424e9911ae2e7fa1c18b247effdeebb68da1c5c5e3c0dcfc9122eb7904410edcdbf75ab832bdcc1c6a76ad521a3",
    "f94343e29b54a0f31b9d28d5f2b2ff3a37abbff9ef87606f9faede15105dcc45f0b648d7bccf45ca669cf6a10471acbe4937c4eb2de91686f7dd24d1",
    "871ac3fafcb8ae446c0b35bda383f004e4ad23671ff78f46a3ee02fa92ae7c02a0f8388dd1c0549da3b7e6c9f538463000ac8853f0109c1ae97689a4",
    "a2c6d982a33a4bf0ec8e5c8568c7b9b78b37e8f83d64e609ff8e6c433e3ef419dd20014badfae82f24714c6df5bb30327c398a5d499008e7995df10d",
    "602626c4b453392f4a9debc04e214690be865d9721733900be168fc47cd3f729e962f1b1454a25fa1282f66f9bfe610534f2e15546fc24d6788d8723",
    "21535d6e11c44fe5b7a6ba0a94f228205b18a85f1bdd9066c1f0788188b6f2248fdd3c248e2d68f3828c8944d01bc9c0426e8f1e2e115d8cccd97e05",
    "21ee08e34f35efbe90123321385a08fa3a4ad7568e55013ff5181513e71224e89a261a84bd1b4b42201161ec2be921dec620b9886d4afab6347e920a",
    "dfeee0142d202b7b2080d9ae3cb4770f9e6dbe475a271aaf80433d17b0c8149f20e6d507692fd41520caffae1467842cc9a0e8997c2e236f80c7e69a",
    "e35f802a9130a2d8984f0510375b52e188af72224b2d0565b9ffa155b6d3a4829e279724542217a1f45ff21a31c7214fa955ac0d8b8500294acd1b41",
    "7077630ed9f31cd1207047b2bef57d8004134cac772f88881a1905d819fba3471ff0cba605d94b22a9dfba04c8ac251eac6309ae077bfe0a56129cac",
    "1af1233d9260578bf1c893b31d70b67997d686955f7396f5a3f53093bf37203d18ff19a5894f4222332fb7149d4ea851052ab19cdce5e7e6641f7414",
    "1e2677dd51226a802c210545000c54865a5731fb796bbbdb7918e19e35d547e9c63a87336da585c07eaaa56bcdd6b20fde0a3e32817709667530c630",
    "2caf9c37e43d21e4930d32d08370cca4c0ff2ebf8e71a6b5711be8e736a23ea1db8c5b08a75078e9c1d3aaefbe2fa58d0d03bac67dd22fbd23797a95",
    "77ad2f8e9afd578856552a860eb6fbf1f3a5d8a246580ea54a60d043d92ddeb7a61a4b06c69e3dfdb51a4a138048aa7356afa0257862ead640f58e76",
    "2cc5a04ffcc5a730752f6beb57e11dfebc37ed45540ef2df8ad9a95dbc7160be7eb4e62f10525f0018b0777dcc2237f58713c4d157277986a740dbf3",
    "8d6ff727f87bb411ed6e2156800a258419d168af888f17fc2073cdd81f1e6508168e427271a369c2a89098698d37485fd9c510a41eac57626ae16cd3",
    "197c4b337d1c617e128735da7ebb8b772088153a4cf16f994683b9f25f9f0b69eb975a4985ff347da82e3fa7d7d4f4f7eacbe68b21083f0feeaab807",
    "91b8fbaf623157e8eca71330b4ff50c63bd6dec6998a898a773dab196c9f180f2ec0731d14a9f13c040bb8df17de6ac5c5aa3be7f96f0ee89a11d056",
    "44e564ecf4a8fcaf0c1b78165ab4fc3d38c9253edd3df6e70d23c5449cf6acd136f8ba8793447f8b731f6984c9d100884392a09a678936f0286ef7f4",
    "ff5db00540913f47fbc6d1712ce8788f1a77fd60ac4ded2073a924aeec1f25aad3a09e43b76a2a4722f4fd21685f19cfd37905a26dd4711cad41aaa2",
    "3aa8856b67418a05803664eba88ebc57b3d9b9fb7be9ddac8441aee32ac758b670d2a171866a79d306db9f643d884f1e6c0fa29761bc7f9d746b473e",
    "5d49bfcdee3c36a1af8ee7faef5a0034be61368525a8eaa28dfb93cb59ee0af878168906ff3444af028146d6b51572cca674b8ca4746b29cfbc69b3d",
    "564a8c3b7d9d1934005d9a658af1e57416cd805d0300fb28551c4ab454deee1fdbb45f9b9ef77ff2a67e3de8eea4b4160db2092c4812360462e02689",
    "eaa9b8488d8245ba4ca60a08c26e0662fdddcd3487d5c392688a8585c0e259b181a35f33a84e19e782b47f7ab718ea8bf1248b8aa6a63b634927323f",
    "1ba52dd44bac3ad7aa19eccb5e25eb9a313b06d3b2a55537370475076dd095d5d1e3e2441a66a68503fd2a4dbc3348e9eeb3b9198cc265f752e53ad4",
    "75786d5906e108d1eb9639126099d2bcb03f21808c068c250456699ff055184b86763f9afbe8c19f88fb49712ce23b8a695eea189a22409eca2a793d",
    "42124d74ec0900b83e35ef686aa51977a7b93070a29335cb762c1df372a1b5f7faa255616cc53ed3f0f0a2fe21e484c0e7fabc0402c2387a0288083e",
    "a92c56549ee6afc53369c20504fd9ced6023cea406319bfa22818d66141625afd8ea822ea42c24094230fb9601fb5a8a4c2c80d95ad6d06339574de0",
    "8d1ecda1c16564e1db4e613b8951f4b2ef108b0d965f9beff60467e6e69e6a38310989a33dd6b49fba04c9b8c6da2b3a660b43de10cfae5b8cf4a6fc",
    "4052171e7d73aafaac4cff7af5b2e2cb0d03ee2e0533df9c636c09252bf61cdbe2afe820001a1fdaea8ca853d7263c632d48d986bbe0f9b7b5520830",
    "925766101f329b322343a2a5d04780a11ad9080259d305216d44472f00927a143e980e5d8079b03bf425084b2ddefa6d1f7577f3e3584ccfd028b92d",
    "221ff9e38989db8943365305b458be5220dd1782c5697701cc90c5e85143b77e678a46b299c5666c66ff2bf1f0120f28f4042ee769db65e1d2575591",
    "e415711f0830f0db80a0b68751b20b1d41cb42fae559909c16b4b15d920e814abf8f6a8c8d98414de953064123ca984d08a978f51aa19f421f0233b1",
    "3a02069f276121d7cfac24c27b462252cdeef2c764f70c0680b18e7b6285eb4c5e671d042e862aad069ab4897e935d7260fd211af1e1df7eee906c85",
    "f696370914d13d09fbb76c345f5f7656f3a08da574e43f45eeaff7eb391d7a0a43e7ee64873256c5b5301cc0cd11415b1cdb708dc4d20bb72f11e731",
    "c0230dfa8226a23cdaba6c2764ce3881b37010529f66fb6f7d58e8ae0c7d4337ea7253f6b912dbff136953ac1e26a9783a1c5a1a446245baee4f4d65",
    "88e52f3a29dbc5549c5380874c58df9b5ec580d66b6e50474e246572a59b91e016644ef0538d8986360741ac91e965acd04eb78c5a266ec6214b1fb5",
    "df000a25afc9d0181a54788c05eea198cd7b1992cacb40cfdf27a99f0d298ab948610fb16baf4fc69693d4c945a745cc2a515011dec05553e483fb01",
    "05126a01a5848875d27574b88d410a405f102bc0f8854d5dfe093280f395a4e31249daa376a63aa449f051e1c97f11cd4355f2808b70615dc8db4cb6",
    "d9923871ca537b472ebde1fb14edfac7fa80da859b4164f065e5508994d547fc5590b919acce241e204c50e62965b06d445b7af2260f1fbc8bcff362",
    "ab2acf97198ddbd5a10f3b17d79653d6a656dbedbc25a555a0be6f02f14236a4339237aef39800d6f24ecce887aaedde0169a05b9ef52ad2c3238683",
    "aaca3ae1d373b46c248c269a89fc088588add2f7a7b775e8ec0362285c4325084d47b4ff32f8c5321199f03fb3bd248593f8feabe0ba33ebae9d5c5a",
    "6809721c9c8269115b3721868e9a8df634f37b72921324d7974a5e88dbee71c289a35636ace2055f52d339a6ff0b38e3b4cc8a3d3b47bbd096198858",
    "742038d60c97c482070c44f3214c8d67b662d225b81a08d5aa2e015a36f83046d802cf5b74fd4605dfee0feb125bbacf66db5bed0ecfee78efa1a671",
    "a5fc4798d43fddeb8d266368c7b4a98511c637115c3367b99577c2aba2cb38a587530e9c42317ff67c21f06af32171e0dd681b395080868520903f05",
    "8d40cb0e6d0421c0928331529274db6b1d3edad63cef40a25d70d1efea8a415223fdba6b3f499c958a124f69b1ff6f5a97dd141bf18d6a161aadd527",
    "4f9543597bf1b71042d1874ecfe6617c0b45576b38e1bc353c2d5d54185a8ef8c1bb6f35c09fea087f0c84c85a75f168dfb3309705e18827c52e697d",
    "67c1582a8e7828165a602e054f51d028d0829debf8b7fc6c080eb49c685c3a8dc32204d2b63e82ffaefcd2fb6002e27060efd3cbb33846755e9c33b3",
    "9626a8391ef33d0f731b641e1f73e4c72e445e18156adc9d5a861568b515cd3b445450fb46a78416dcbbce45e342a144f550db0102a5296d378be18a",
    "6d3f8b015de15ced3979839ada6b6f50eb0b6c89cea6587d44b697fc32caa3a76fbac8fb0c36ca677d1634913e802ece1013ba9628f75260199583e4",
    "fb8826d460fbcebe9efe246a4108a1786b4042b93219ea6d022c4041f873bb5a7017c112f9a25c5e1fd538ad3adaec4f70a18372b1b4624b350c58fa",
    "f361b7ecefc77a144c11fe58036f0d324af7291e6aba0f9e9568e70ddbc8e38d5f851b829d4e9df5cfb3fa5edc855e8c725044639c597d02b98a4f26",
    "7260013a641ee380a5570cc839216e9d82be8339d82d459472c8378f44439f989def3649e726dd01807ecbe4bc7da21b923b859be2ab2875e4f505aa",
    "d6c2fc06f414eb573e2acd4739756cd9f566d27d7eb0f080af2e0d6ec1b5c3e120ddbd2dc747dbbdc398047f72620bf299526b50d821454faf9d3c1b",
    "710e709239d553bf86448003f29abd0d2157c09297d9118bde3b945bcbcd968b372a56b923cbc072ad4ec45a667e9467aaad626e8929dc7ad625d58f",
    "7ae112788ec836dedf42af0e1a9b2993ee2c8dde7a6d0c4c7bdf8ccfd025257081894078ed87055640e6eca1cbc5e5ae85afecb7c9440ad825d33b96",
    "e23cfc9a0ea94a8bb30957bae3b2140d04048757462b437c284896439e8b7e3d53e57324b7966e3d2f9d794e6489aed654e89a4fc49b48a4917e3400",
    "6cd2144b423db35bdea0fbde0211a926367566d67df9d00bde0bec237a4c14eee7a4bb4e09b558dcb75af2e8e3656c487452dbb71b999979661383f1",
    "65623f7bf5fed30974160e0b7d129ae3ccfc612211d58cae026af3268251b163a4827cc61b1e0074182974b957fed3e66001ac4ae25519ba46830f30",
    "f490aa7f2027b567ea7949c25d71f525374eaf851aa1a7f7a88196bfad7d69e1941b8dc8c5dc325030aae297b6cf8a674fa1455865d15f85b5562f71",
    "1d380f85259c8c715002c7bd9653a2e7fd6ea6f3a257d547a660d0829427cb9675e2be5e36ee1fe9ca103dc663a7633eaaaa8b9efbdf06f810408fbd",
    "7760f7d3ca6c2544a5e5d5e4aa08bfc1763ffa8e590ee561935994f6bb8e1f6bd7804510125d6a5dc18d11f6d4788da73be187628a68e7eb795028a8",
    "18c83c6487d38818cc88d0d0c6ce054af38240b1ea7bca233a4e42710b17b299292ecbcb58925a4d0f4c7c811feb49c3c958c34b4da084c3b7500ac1",
    "af6feeec9c16beffa36a06da41ad475c3539995d62bffcf7ebdda90dcd455275e9e820bb364d49f03046cb228a874ba68d21c1898e467ac138e50e45",
    "925a76be3cdddad3c285b2eb7cd49af45a96f0255260c7f3aaba27174481e19fb0c5c72dbf8f5a1fec6c59d9b14fa5ef0c0143fd6be910f01c217380",
    "21a3b1a88c325237d8c26347fbc0e357066cbb5b5f4cfdea0e7b41643d294df7c45be0089c7e56300b60c675bafd6bca44db02e27ba7",
}

local STRINGS_HEX = {
    "7c04fcffba03078ad1747f4c6dec0a5fb82776f8286400ed420b0690f03d77e4c440f64f2a07d774be0de3b28c0997799979e05e3e1464085a445b4a",
    "9817d4481516391a2e2cdd421b6a0db4343c343b2c29d8511b6d09d90ede028c9fc64646043dac1f2c04f08dc31206544a5540f42007285a74787630",
    "140778257a6b70b9680515ce620aa840daf5303677321e7287bca353daf0306d7d631f2ed7eca203ddf563382f36197d87eaa70989f5666b7f601c78",
    "85b8a001def0373b79314e73dcb7f7068ff2603b087856424652565557035f5d460677575d56564a0a054a78017259596308050c625d4573474c445b",
    "52454e540d765d4573474c445b52454e544b0c765d4573474c445b52454e5406454141575c5e07755d424641574f047456445f086159434667414657",
    "0c765d45775d4d5b7b44555742044541415707675d52465c4a0501690168016b0456595c570b77515f56605d444459535f087d51565a475158550a76",
    "5d4561564a405b535509725450414076575f5509654f54575d7158545f0b7459425b5d5f6546495c5f04735952590f7459425b5d5f725b4255594551",
    "5e56037e4d450465515c570b635d4157524c755d455e4e08635d4757414b534109755d5d534a6c5f5f550a734a5851587b595e5f420c635d505e5f41",
    "16505c51595a047f595c57067f4d5c50564a0966574359404857515509465743594048575155077250505c545d520663595f565c550572545e5c560b",
    "7f5d49467a5642575755480e7f4d5c50564a655741455f5f5b57167f4d5c50564a655741455f5f5b5778504048595f5e45097a5d48425c5158464305",
    "67595d475608745647575f57465709774a5e5f65595a4755087456445f6741465708774a5e5f7d595b5704647c585f05625b505e56067e5e5741564c",
    "05724a5e41400375574511635d415e5a5b5746555469455740585253076154504b564a4503784b700f625d43445a5b5362425f4c585c574b0a634d5f",
    "61564a405b5355095257435d464c5f5c5507434d5f5c5a56510453414557045c59455a035c59490557545e5d4107675d52465c4a040b794c4542605d",
    "444459535f05415b505e5f03424d530672575d5d410b01630176017304615943460e7062694b590a00736549584b755b0462514b57085f5d46424157",
    "4e4b0578565f57410c097b54757d7e596275605c650c6b5d5459415951476a610a4906615943575d4c0b765d457446545a7c515d5f0b7f4d5c50564a",
    "64535e575f037c515f037c5949057c5755575f0b765d45715b515a564255540e77515f56755144414473525854501577515f56755144414473525854",
    "507c577154574b451677515f5675514441447352585450645950575a7b40700843594657424d575e047d5d434204635d524640030e0554005b010102",
    "0309000d565f050605525206545a070a0608505051060d505b00580a050c070307030105530a0b525309060d570e560c0150555553575340080c0750",
    "06590e0003030f5409500c0e500a035709010d54040a090057530102045a570d5a0052075501525c530007005401065502575d040b0a050455530105",
    "4008085051515c0653040902050b000a03520750065455000305505a570207520a525d020302010051050957595050520d0703075308570b52055155",
    "5105020452400209030305080f5306080e010a0701030d50030759570b02000a5a520400075c010d5407010c5055020c025c03070700555008075904",
    "0853050d0e04040d0e5306424c435b5d5f065757435f524c0514160005540e54106a191e651f021b181f55131805541d00170104564b445005647c58",
    "5f010c765d5f5741594257776573750d47705c7c69086605636a68085014407748676708477b057f6f63535760075e0051070441594346",
}


----------------------------------------------------------------------------
-- small helpers
----------------------------------------------------------------------------

local function bxor(a, b)
    if bit32 then return bit32.bxor(a, b) end
    local r, bit = 0, 1
    for _ = 1, 8 do
        local x, y = a % 2, b % 2
        if x ~= y then r = r + bit end
        a = (a - x) / 2
        b = (b - y) / 2
        bit = bit * 2
    end
    return r
end

local function unhex(hex)
    local out = {}
    for i = 1, #hex, 2 do
        out[#out + 1] = string.char(tonumber(string.sub(hex, i, i + 1), 16))
    end
    return table.concat(out)
end

local CIPHERTEXT = unhex(table.concat(SLICE2_HEX))
local STRINGTABLE = unhex(table.concat(STRINGS_HEX))

local function quote(s)
    local safe = string.gsub(s, "[^\32-\126]", function(c)
        return "\\" .. string.byte(c)
    end)
    return '"' .. safe .. '"'
end

----------------------------------------------------------------------------
-- layer 2: the number cipher
----------------------------------------------------------------------------

local MOD = 2147483647

local function decrypt(data, key)
    local a1 = key[1] % MOD
    local a2 = key[2] % MOD
    local a3 = key[3] % MOD
    local out = {}
    for i = 0, #data - 1 do
        local p, q, r = a1, a2, a3
        a1 = (p * 48271 + q * 131 + (i + 1) * 7919   + 17) % MOD
        a2 = (q * 65599 + r * 257 + (i + 1) * 40503  + 31) % MOD
        a3 = (r * 31337 + p * 193 + (i + 1) * 104729 + 73) % MOD
        local pad = bxor(bxor(a1 % 256, a2 % 256), a3 % 256)
        out[#out + 1] = string.char(bxor(string.byte(data, i + 1), pad))
    end
    return table.concat(out)
end

----------------------------------------------------------------------------
-- layers 4, 5 and 6: the string cipher, the same key repeated
----------------------------------------------------------------------------

local function repeatXor(data, material)
    local out = {}
    local n = #material
    for i = 0, #data - 1 do
        local k = string.byte(material, (i % n) + 1)
        out[#out + 1] = string.char(bxor(string.byte(data, i + 1), k))
    end
    return table.concat(out)
end

-- sq, exactly as the file builds it: a hex literal, first eight digits
local SQ = tonumber("021060a4", 16)
local LQ = "1812386200"
local MOD2 = 2147483629
local MAGIC = "MYqme"

local function constMaterial(g)
    return tostring((g * 7919 % MOD2 + SQ) % MOD2)
end

----------------------------------------------------------------------------
-- layer 3: the reader. One reader, two modes: the function reader inverts its
-- length bytes, the constant reader does not.
----------------------------------------------------------------------------

local TAG_NIL, TAG_FALSE, TAG_TRUE = 134, 222, 202
local TAG_NUMSTR, TAG_INT, TAG_DOUBLE = 15, 60, 236
local TAG_STRING, TAG_TABLE = 161, 174

local WRAP_CONST, WRAP_TEXT, WRAP_PROTO = 68, 0, 194

local function newReader(data, pos, inverted)
    local R = { data = data, pos = pos }

    function R.uint()
        local total, scale = 0, 1
        while true do
            local b = string.byte(R.data, R.pos)
            if b == nil then error("ran off the end at " .. R.pos) end
            if inverted then b = 255 - b end
            R.pos = R.pos + 1
            total = total + (b % 128) * scale
            if b < 128 then return total end
            scale = scale * 128
        end
    end

    function R.int()
        local v = R.uint()
        if v % 2 == 0 then return v / 2 end
        return -(v + 1) / 2
    end

    function R.str()
        local n = R.uint()
        local s = string.sub(R.data, R.pos, R.pos + n - 1)
        R.pos = R.pos + n
        return s
    end

    function R.value()
        local tag = string.byte(R.data, R.pos)
        R.pos = R.pos + 1
        if tag == TAG_NIL then return nil end
        if tag == TAG_FALSE then return false end
        if tag == TAG_TRUE then return true end
        if tag == TAG_NUMSTR then return tonumber(R.str()) end
        if tag == TAG_STRING then return R.str() end
        if tag == TAG_TABLE then
            local t = { arr = {}, map = {} }
            local n = R.uint()
            for i = 1, n do t.arr[i] = R.value() end
            local m = R.uint()
            for _ = 1, m do
                local k = R.value()
                t.map[k] = R.value()
            end
            return t
        end
        if inverted then
            if tag == TAG_INT then return R.int() end
            if tag == TAG_DOUBLE then
                local v = 0
                if string.unpack then v = string.unpack("<d", R.data, R.pos) end
                R.pos = R.pos + 8
                return v
            end
        end
        error("unknown tag " .. tostring(tag) .. " at " .. (R.pos - 1))
    end

    return R
end

-- the field order is the file's own. The slot numbers are what its interpreter
-- indexes, kept here so this can be checked against it line by line.
local function readFunction(data, pos)
    local R = newReader(data, pos, true)
    local fn = {}
    fn.lineBase = R.uint()                                     -- slot 12
    fn.upvalues = R.int()                                      -- slot 14
    fn.header = R.value()                                      -- slot 1

    fn.numbers = {}                                            -- slot 11
    local n = R.uint()
    for i = 1, n do fn.numbers[i] = R.int() end

    fn.children = {}                                           -- slot 10
    n = R.uint()
    for i = 1, n do
        local len = R.uint()
        fn.children[n - i + 1] = { offset = R.pos, length = len }
        R.pos = R.pos + len
    end

    fn.flags = R.value()                                       -- slot 8
    fn.params = R.uint()                                       -- slot 9

    fn.constants = {}                                          -- slot 17
    n = R.uint()
    for i = 1, n do fn.constants[i] = R.value() end

    fn.mode = string.byte(data, R.pos)                         -- slot 16
    R.pos = R.pos + 1
    fn.extra = R.value()                                       -- slot 7
    fn.stack = R.int()                                         -- slot 15
    fn.names = R.value()                                       -- slot 6
    fn.jumpKey = R.int()                                       -- slot 3
    fn.count = R.int()                                         -- slot 4
    fn.tail = R.value()                                        -- slot 5

    fn.steps = {}                                              -- slot 2
    n = R.uint()
    for i = 1, n do
        local one = {}
        local w = R.uint()
        for j = 1, w do one[j] = R.value() end
        fn.steps[i] = one
    end

    fn.jumps = {}                                              -- slot 13
    n = R.uint()
    for i = 1, n do fn.jumps[i] = R.value() end

    fn.bytesRead = R.pos - pos
    return fn
end

----------------------------------------------------------------------------
-- the string table's own index: a count, then a length per entry
----------------------------------------------------------------------------

local function stringIndex(table3)
    local R = newReader(table3, 1, false)
    local out = {}
    local n = R.uint()
    for i = 1, n do
        local len = R.uint()
        out[i] = { offset = R.pos, length = len }
        R.pos = R.pos + len
    end
    return out
end

local INDEX = stringIndex(STRINGTABLE)

----------------------------------------------------------------------------
-- layer 4 then layer 5, for one constant
----------------------------------------------------------------------------

local function unwrapConstant(c)
    if type(c) ~= "table" then return "plain", c end
    local arr = c.arr
    if arr[1] == WRAP_PROTO then return "packed function", c end
    if arr[1] ~= WRAP_CONST or #arr < 3 then return "other", c end
    if c.map[4] == 1 or arr[4] == 1 then return "needs the measured key", nil end
    local inner = repeatXor(arr[2], constMaterial(arr[3]))
    local R = newReader(inner, 1, false)
    local ok, value = pcall(R.value)
    if not ok then return "would not read", nil end
    if R.pos ~= #inner + 1 then return "did not use its bytes", nil end
    return "ok", value
end

local function resolveText(v)
    if type(v) ~= "table" then return nil end
    local arr = v.arr
    if arr[1] ~= WRAP_TEXT or #arr < 3 then return nil end
    if v.map[4] == 1 or arr[4] == 1 then return nil end
    local slot = arr[2]
    local e = INDEX[slot]
    if not e then return nil end
    local raw = string.sub(STRINGTABLE, e.offset, e.offset + e.length - 1)
    return repeatXor(raw, LQ .. ":" .. tostring(arr[3]))
end

----------------------------------------------------------------------------
-- walk it all
----------------------------------------------------------------------------

local function describe(v)
    local t = type(v)
    if t == "string" then return quote(v) end
    if t == "number" then
        if v == math.floor(v) then return string.format("%d", v) end
        return tostring(v)
    end
    if t == "boolean" then return tostring(v) end
    if v == nil then return "nothing" end
    if t == "table" then
        local parts = {}
        for i = 1, #v.arr do
            local x = v.arr[i]
            parts[#parts + 1] = type(x) == "string" and (#x .. " bytes") or tostring(x)
        end
        return "{ " .. table.concat(parts, ", ") .. " }"
    end
    return t
end

local names = {}        -- every piece of text any layer gave up
local packed = {}       -- the layer 6 functions, waiting for a key to try

local function readConstants(fn)
    local rows = {}
    for i = 1, #fn.constants do
        local state, value = unwrapConstant(fn.constants[i])
        local row = { index = i, state = state, value = value }
        if state == "ok" or state == "plain" then
            local text = resolveText(value)
            if text then
                row.text = text
                row.state = "text"
                names[#names + 1] = text
            elseif type(value) == "number" then
                names[#names + 1] = tostring(value)
            elseif type(value) == "string" then
                names[#names + 1] = value
            end
        elseif state == "packed function" then
            packed[#packed + 1] = row
        end
        rows[i] = row
    end
    return rows
end

local functions = {}

local function readAll(data, pos, path)
    local fn = readFunction(data, pos)
    fn.path = path
    fn.rows = readConstants(fn)
    functions[#functions + 1] = fn
    for i = 1, #fn.children do
        readAll(data, fn.children[i].offset, path .. "." .. i)
    end
    return fn
end

-- layer 6: try what the file already gave up, keep what the magic confirms
local function openPacked()
    local openedAny = 0
    for round = 1, 8 do
        local progress = false
        for _, row in ipairs(packed) do
            if not row.opened then
                local arr = row.value.arr
                local blob = arr[2]
                for _, material in ipairs(names) do
                    if #material > 0 then
                        local try = repeatXor(blob, material)
                        if string.sub(try, 1, 5) == MAGIC then
                            row.opened = material
                            local sub = readFunction(try, 6)
                            sub.path = "packed:" .. tostring(arr[3])
                            sub.rows = readConstants(sub)
                            functions[#functions + 1] = sub
                            openedAny = openedAny + 1
                            progress = true
                            break
                        end
                    end
                end
            end
        end
        if not progress then break end
    end
    return openedAny
end

----------------------------------------------------------------------------
-- run
----------------------------------------------------------------------------

print("real.lua")
print("layer 1: " .. tostring(#CIPHERTEXT) .. " encrypted byte(s), plus a "
      .. tostring(#STRINGTABLE) .. " byte string table")
print("string table entries: " .. tostring(#INDEX))

if KEY == nil then
    print("")
    print("layer 2 needs the key, and the key is not in the file. It is three")
    print("numbers the first layer measures off the machine it runs on. Put")
    print("them in KEY at the top and run this again.")
    print("")
    print("You will know at once: the first five bytes come out as MYqme when")
    print("the key is right, and as noise when it is wrong.")
    return
end

local plain = decrypt(CIPHERTEXT, KEY)
local head = string.sub(plain, 1, 5)
if head ~= MAGIC then
    print("")
    print("layer 2 failed. first five bytes: " .. quote(head))
    print("expected: " .. quote(MAGIC))
    print("")
    print("The key is wrong. The file's own reader makes this same test and")
    print("refuses the data, which is why a wrong key ends in an error about")
    print("indexing a number. Nothing here is broken. Change KEY.")
    return
end

print("layer 2: ok, " .. tostring(#plain) .. " byte(s) decrypted")
print("layer 3: reading")

local top = readAll(plain, 6, "main")
print("layer 3: " .. tostring(#functions) .. " function(s), "
      .. tostring(top.bytesRead + 5) .. " of " .. tostring(#plain) .. " bytes used")

local opened = openPacked()
print("layer 6: " .. tostring(opened) .. " packed function(s) opened")
print("")

local texts, numbers, held = 0, 0, 0
for _, fn in ipairs(functions) do
    for _, row in ipairs(fn.rows) do
        if row.text then texts = texts + 1
        elseif row.state == "ok" or row.state == "plain" then numbers = numbers + 1
        else held = held + 1 end
    end
end
print("constants: " .. tostring(texts) .. " as text, " .. tostring(numbers)
      .. " as values, " .. tostring(held) .. " still wrapped")
print("")

for _, fn in ipairs(functions) do
    print(fn.path .. ": " .. tostring(#fn.steps) .. " step(s), "
          .. tostring(fn.params) .. " parameter(s), jump key " .. tostring(fn.jumpKey))
    for _, row in ipairs(fn.rows) do
        if row.text then
            print("    " .. row.index .. "  " .. row.text)
        elseif row.state == "ok" or row.state == "plain" then
            print("    " .. row.index .. "  " .. describe(row.value))
        else
            print("    " .. row.index .. "  [" .. row.state
                  .. (row.opened and (", opened under " .. quote(row.opened)) or "") .. "]")
        end
    end
    for i, step in ipairs(fn.steps) do
        local parts = {}
        for j = 1, #step do parts[#parts + 1] = describe(step[j]) end
        print("    step " .. i .. ": " .. table.concat(parts, " "))
    end
    print("")
end

print("names the layers gave up: " .. tostring(#names))
