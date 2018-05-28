# Benchmarking non-crypto hashes for hashtables / rendezvous hashing

I found myself in need of a hash function that was uniform and would do a
good job of turning user-supplied UUIDs (which are often not very random)
into a nice uniform integer for partitioning purposes.

Of course, there are many good hash functions out there, but the key is
in the implementation, a bad implementation of a good hash is useless.


## Implementations

The code for these implementations comes from:

```
xxhash "github.com/OneOfOne/xxhash"
murmur2 "github.com/aviddiviner/go-murmur"
xxhashfast "github.com/cespare/xxhash"
dchestsip "github.com/dchest/siphash"
"github.com/dgryski/go-farm"
highway "github.com/dgryski/go-highway"
"github.com/dgryski/go-marvin32"
"github.com/dgryski/go-metro"
"github.com/dgryski/go-sip13"
"github.com/dgryski/go-spooky"
"github.com/dgryski/go-stadtx"
"github.com/dgryski/go-t1ha"
farmhash "github.com/leemcloughlin/gofarmhash"
"github.com/opennota/fasthash"
"github.com/rbastic/go-zaphod64"
murmur3 "github.com/spaolacci/murmur3"
"github.com/surge/cityhash"
tsip "github.com/dgryski/trifles/tsip/go"
```

## Results

Intel(R) Core(TM) i7-6560U CPU @ 2.20GHz
```
Benchmark32CRC32/4-4     	100000000	        23.5 ns/op	 170.55 MB/s
Benchmark32CRC32/8-4     	50000000	        29.5 ns/op	 270.78 MB/s
Benchmark32CRC32/16-4    	50000000	        35.4 ns/op	 452.45 MB/s
Benchmark32CRC32/32-4    	30000000	        44.4 ns/op	 721.19 MB/s
Benchmark32CRC32/64-4    	100000000	        23.7 ns/op	2705.42 MB/s
Benchmark32CRC32/96-4    	50000000	        29.2 ns/op	3288.34 MB/s
Benchmark32CRC32/128-4   	50000000	        27.0 ns/op	4739.30 MB/s
Benchmark32CRC32/1024-4  	20000000	        76.9 ns/op	13313.33 MB/s
Benchmark32CRC32/8192-4  	 3000000	       471 ns/op	17372.81 MB/s
Benchmark32Marvin/4-4    	200000000	         7.98 ns/op	 501.53 MB/s
Benchmark32Marvin/8-4    	100000000	        10.1 ns/op	 789.92 MB/s
Benchmark32Marvin/16-4   	100000000	        13.3 ns/op	1204.58 MB/s
Benchmark32Marvin/32-4   	100000000	        18.8 ns/op	1703.51 MB/s
Benchmark32Marvin/64-4   	50000000	        33.4 ns/op	1916.22 MB/s
Benchmark32Marvin/96-4   	30000000	        47.2 ns/op	2034.24 MB/s
Benchmark32Marvin/128-4  	20000000	        61.2 ns/op	2092.90 MB/s
Benchmark32Marvin/1024-4 	 3000000	       466 ns/op	2197.10 MB/s
Benchmark32Marvin/8192-4 	  500000	      3754 ns/op	2181.69 MB/s
Benchmark32MurMur3/4-4   	100000000	        11.4 ns/op	 350.04 MB/s
Benchmark32MurMur3/8-4   	100000000	        12.9 ns/op	 618.47 MB/s
Benchmark32MurMur3/16-4  	100000000	        15.3 ns/op	1046.53 MB/s
Benchmark32MurMur3/32-4  	100000000	        21.0 ns/op	1526.07 MB/s
Benchmark32MurMur3/64-4  	50000000	        34.0 ns/op	1880.71 MB/s
Benchmark32MurMur3/96-4  	30000000	        46.6 ns/op	2058.64 MB/s
Benchmark32MurMur3/128-4 	20000000	        66.1 ns/op	1936.54 MB/s
Benchmark32MurMur3/1024-4         	 3000000	       464 ns/op	2203.17 MB/s
Benchmark32MurMur3/8192-4         	  500000	      3658 ns/op	2239.17 MB/s
Benchmark32MurMur2/4-4            	200000000	         8.12 ns/op	 492.49 MB/s
Benchmark32MurMur2/8-4            	100000000	        10.6 ns/op	 753.83 MB/s
Benchmark32MurMur2/16-4           	100000000	        14.1 ns/op	1133.15 MB/s
Benchmark32MurMur2/32-4           	100000000	        23.3 ns/op	1374.71 MB/s
Benchmark32MurMur2/64-4           	50000000	        37.7 ns/op	1697.15 MB/s
Benchmark32MurMur2/96-4           	30000000	        54.9 ns/op	1750.15 MB/s
Benchmark32MurMur2/128-4          	20000000	        69.6 ns/op	1838.40 MB/s
Benchmark32MurMur2/1024-4         	 3000000	       520 ns/op	1965.62 MB/s
Benchmark32MurMur2/8192-4         	  300000	      4141 ns/op	1977.85 MB/s
Benchmark32MurMur2a/4-4           	200000000	         9.47 ns/op	 422.44 MB/s
Benchmark32MurMur2a/8-4           	100000000	        11.5 ns/op	 695.97 MB/s
Benchmark32MurMur2a/16-4          	100000000	        15.2 ns/op	1049.30 MB/s
Benchmark32MurMur2a/32-4          	100000000	        24.8 ns/op	1288.21 MB/s
Benchmark32MurMur2a/64-4          	50000000	        40.2 ns/op	1590.18 MB/s
Benchmark32MurMur2a/96-4          	30000000	        54.4 ns/op	1765.04 MB/s
Benchmark32MurMur2a/128-4         	20000000	        70.2 ns/op	1822.22 MB/s
Benchmark32MurMur2a/1024-4        	 3000000	       516 ns/op	1982.59 MB/s
Benchmark32MurMur2a/8192-4        	  300000	      4177 ns/op	1960.80 MB/s
Benchmark32cityhash/4-4           	100000000	        13.8 ns/op	 289.27 MB/s
Benchmark32cityhash/8-4           	100000000	        14.5 ns/op	 550.93 MB/s
Benchmark32cityhash/16-4          	50000000	        21.3 ns/op	 752.03 MB/s
Benchmark32cityhash/32-4          	50000000	        32.6 ns/op	 982.03 MB/s
Benchmark32cityhash/64-4          	20000000	        56.6 ns/op	1131.73 MB/s
Benchmark32cityhash/96-4          	20000000	        71.4 ns/op	1345.12 MB/s
Benchmark32cityhash/128-4         	20000000	        94.7 ns/op	1351.01 MB/s
Benchmark32cityhash/1024-4        	 2000000	       629 ns/op	1626.87 MB/s
Benchmark32cityhash/8192-4        	  300000	      5169 ns/op	1584.69 MB/s
Benchmark32Spooky/4-4             	50000000	        22.7 ns/op	 176.27 MB/s
Benchmark32Spooky/8-4             	50000000	        22.6 ns/op	 353.30 MB/s
Benchmark32Spooky/16-4            	50000000	        33.5 ns/op	 477.91 MB/s
Benchmark32Spooky/32-4            	50000000	        35.6 ns/op	 897.86 MB/s
Benchmark32Spooky/64-4            	30000000	        47.0 ns/op	1360.70 MB/s
Benchmark32Spooky/96-4            	30000000	        60.8 ns/op	1579.06 MB/s
Benchmark32Spooky/128-4           	20000000	        67.8 ns/op	1887.78 MB/s
Benchmark32Spooky/1024-4          	 5000000	       297 ns/op	3446.54 MB/s
Benchmark32Spooky/8192-4          	 1000000	      1922 ns/op	4261.66 MB/s
Benchmark32Farm/4-4               	100000000	        13.0 ns/op	 306.95 MB/s
Benchmark32Farm/8-4               	100000000	        14.3 ns/op	 560.98 MB/s
Benchmark32Farm/16-4              	100000000	        16.8 ns/op	 953.09 MB/s
Benchmark32Farm/32-4              	50000000	        26.2 ns/op	1220.59 MB/s
Benchmark32Farm/64-4              	30000000	        40.9 ns/op	1566.24 MB/s
Benchmark32Farm/96-4              	30000000	        47.0 ns/op	2042.96 MB/s
Benchmark32Farm/128-4             	20000000	        61.1 ns/op	2093.81 MB/s
Benchmark32Farm/1024-4            	 5000000	       363 ns/op	2819.54 MB/s
Benchmark32Farm/8192-4            	  500000	      2815 ns/op	2909.97 MB/s
Benchmark32XXHash/4-4             	100000000	        11.0 ns/op	 364.35 MB/s
Benchmark32XXHash/8-4             	100000000	        12.9 ns/op	 621.88 MB/s
Benchmark32XXHash/16-4            	100000000	        13.6 ns/op	1176.22 MB/s
Benchmark32XXHash/32-4            	100000000	        16.5 ns/op	1942.05 MB/s
Benchmark32XXHash/64-4            	50000000	        23.6 ns/op	2711.36 MB/s
Benchmark32XXHash/96-4            	50000000	        30.2 ns/op	3177.64 MB/s
Benchmark32XXHash/128-4           	30000000	        36.1 ns/op	3543.06 MB/s
Benchmark32XXHash/1024-4          	10000000	       195 ns/op	5248.85 MB/s
Benchmark32XXHash/8192-4          	 1000000	      1466 ns/op	5587.15 MB/s
Benchmark32FarmHash/4-4           	100000000	        15.2 ns/op	 263.56 MB/s
Benchmark32FarmHash/8-4           	100000000	        17.6 ns/op	 455.66 MB/s
Benchmark32FarmHash/16-4          	100000000	        21.9 ns/op	 730.51 MB/s
Benchmark32FarmHash/32-4          	50000000	        32.5 ns/op	 985.76 MB/s
Benchmark32FarmHash/64-4          	30000000	        51.8 ns/op	1236.34 MB/s
Benchmark32FarmHash/96-4          	20000000	        59.3 ns/op	1618.41 MB/s
Benchmark32FarmHash/128-4         	20000000	        76.6 ns/op	1671.49 MB/s
Benchmark32FarmHash/1024-4        	 3000000	       467 ns/op	2189.94 MB/s
Benchmark32FarmHash/8192-4        	  300000	      3624 ns/op	2260.16 MB/s
Benchmark64MurMur3/4-4            	50000000	        23.5 ns/op	 169.94 MB/s
Benchmark64MurMur3/8-4            	50000000	        26.8 ns/op	 298.26 MB/s
Benchmark64MurMur3/16-4           	100000000	        24.3 ns/op	 659.29 MB/s
Benchmark64MurMur3/32-4           	50000000	        27.0 ns/op	1184.61 MB/s
Benchmark64MurMur3/64-4           	50000000	        32.1 ns/op	1994.86 MB/s
Benchmark64MurMur3/96-4           	30000000	        37.5 ns/op	2561.07 MB/s
Benchmark64MurMur3/128-4          	30000000	        44.4 ns/op	2883.30 MB/s
Benchmark64MurMur3/1024-4         	10000000	       205 ns/op	4973.08 MB/s
Benchmark64MurMur3/8192-4         	 1000000	      1611 ns/op	5083.60 MB/s
Benchmark64MurMur2/4-4            	200000000	         7.78 ns/op	 514.28 MB/s
Benchmark64MurMur2/8-4            	200000000	         9.43 ns/op	 848.34 MB/s
Benchmark64MurMur2/16-4           	100000000	        12.1 ns/op	1322.63 MB/s
Benchmark64MurMur2/32-4           	100000000	        17.6 ns/op	1817.44 MB/s
Benchmark64MurMur2/64-4           	50000000	        29.1 ns/op	2199.65 MB/s
Benchmark64MurMur2/96-4           	30000000	        38.1 ns/op	2519.09 MB/s
Benchmark64MurMur2/128-4          	30000000	        49.0 ns/op	2614.46 MB/s
Benchmark64MurMur2/1024-4         	 5000000	       352 ns/op	2908.18 MB/s
Benchmark64MurMur2/8192-4         	  500000	      2707 ns/op	3025.40 MB/s
Benchmark64Spooky/4-4             	50000000	        22.1 ns/op	 181.10 MB/s
Benchmark64Spooky/8-4             	100000000	        22.6 ns/op	 354.69 MB/s
Benchmark64Spooky/16-4            	50000000	        32.8 ns/op	 488.40 MB/s
Benchmark64Spooky/32-4            	50000000	        34.5 ns/op	 928.45 MB/s
Benchmark64Spooky/64-4            	30000000	        45.7 ns/op	1401.20 MB/s
Benchmark64Spooky/96-4            	30000000	        56.3 ns/op	1704.51 MB/s
Benchmark64Spooky/128-4           	20000000	        67.2 ns/op	1906.15 MB/s
Benchmark64Spooky/1024-4          	 5000000	       304 ns/op	3359.97 MB/s
Benchmark64Spooky/8192-4          	 1000000	      1863 ns/op	4396.95 MB/s
Benchmark64SipHash/4-4            	100000000	        17.0 ns/op	 234.89 MB/s
Benchmark64SipHash/8-4            	100000000	        19.1 ns/op	 419.31 MB/s
Benchmark64SipHash/16-4           	50000000	        23.2 ns/op	 688.24 MB/s
Benchmark64SipHash/32-4           	50000000	        31.9 ns/op	1001.93 MB/s
Benchmark64SipHash/64-4           	30000000	        47.9 ns/op	1335.86 MB/s
Benchmark64SipHash/96-4           	20000000	        64.6 ns/op	1486.21 MB/s
Benchmark64SipHash/128-4          	20000000	        78.1 ns/op	1638.50 MB/s
Benchmark64SipHash/1024-4         	 3000000	       532 ns/op	1924.49 MB/s
Benchmark64SipHash/8192-4         	  300000	      4033 ns/op	2031.07 MB/s
Benchmark64Farm/4-4               	100000000	        12.0 ns/op	 333.70 MB/s
Benchmark64Farm/8-4               	100000000	        14.6 ns/op	 547.79 MB/s
Benchmark64Farm/16-4              	100000000	        14.8 ns/op	1081.37 MB/s
Benchmark64Farm/32-4              	100000000	        18.9 ns/op	1695.06 MB/s
Benchmark64Farm/64-4              	50000000	        25.8 ns/op	2481.76 MB/s
Benchmark64Farm/96-4              	30000000	        46.4 ns/op	2068.69 MB/s
Benchmark64Farm/128-4             	30000000	        47.4 ns/op	2701.11 MB/s
Benchmark64Farm/1024-4            	10000000	       148 ns/op	6893.61 MB/s
Benchmark64Farm/8192-4            	 1000000	      1051 ns/op	7791.47 MB/s
Benchmark64City/4-4               	100000000	        10.4 ns/op	 384.48 MB/s
Benchmark64City/8-4               	100000000	        11.3 ns/op	 707.15 MB/s
Benchmark64City/16-4              	100000000	        11.3 ns/op	1414.68 MB/s
Benchmark64City/32-4              	100000000	        13.6 ns/op	2355.06 MB/s
Benchmark64City/64-4              	50000000	        29.3 ns/op	2182.27 MB/s
Benchmark64City/96-4              	10000000	       129 ns/op	 738.70 MB/s
Benchmark64City/128-4             	10000000	       129 ns/op	 984.84 MB/s
Benchmark64City/1024-4            	 2000000	       632 ns/op	1618.77 MB/s
Benchmark64City/8192-4            	  300000	      4638 ns/op	1766.26 MB/s
Benchmark64Metro/4-4              	200000000	         6.93 ns/op	 577.53 MB/s
Benchmark64Metro/8-4              	200000000	         6.98 ns/op	1145.40 MB/s
Benchmark64Metro/16-4             	200000000	         8.66 ns/op	1847.17 MB/s
Benchmark64Metro/32-4             	100000000	        14.3 ns/op	2235.96 MB/s
Benchmark64Metro/64-4             	100000000	        16.1 ns/op	3969.52 MB/s
Benchmark64Metro/96-4             	100000000	        19.8 ns/op	4858.50 MB/s
Benchmark64Metro/128-4            	50000000	        22.5 ns/op	5697.52 MB/s
Benchmark64Metro/1024-4           	20000000	        90.7 ns/op	11288.68 MB/s
Benchmark64Metro/8192-4           	 2000000	       622 ns/op	13152.54 MB/s
Benchmark64XXHash/4-4             	100000000	        14.6 ns/op	 274.66 MB/s
Benchmark64XXHash/8-4             	100000000	        14.3 ns/op	 560.42 MB/s
Benchmark64XXHash/16-4            	100000000	        16.1 ns/op	 991.02 MB/s
Benchmark64XXHash/32-4            	100000000	        21.4 ns/op	1494.21 MB/s
Benchmark64XXHash/64-4            	50000000	        25.6 ns/op	2501.36 MB/s
Benchmark64XXHash/96-4            	50000000	        28.4 ns/op	3386.06 MB/s
Benchmark64XXHash/128-4           	50000000	        32.5 ns/op	3941.18 MB/s
Benchmark64XXHash/1024-4          	20000000	       103 ns/op	9870.91 MB/s
Benchmark64XXHash/8192-4          	 2000000	       693 ns/op	11811.32 MB/s
Benchmark64XXFast/4-4             	200000000	         7.05 ns/op	 567.69 MB/s
Benchmark64XXFast/8-4             	200000000	         7.62 ns/op	1050.19 MB/s
Benchmark64XXFast/16-4            	200000000	         8.91 ns/op	1795.10 MB/s
Benchmark64XXFast/32-4            	100000000	        14.1 ns/op	2262.80 MB/s
Benchmark64XXFast/64-4            	100000000	        16.5 ns/op	3881.89 MB/s
Benchmark64XXFast/96-4            	100000000	        19.9 ns/op	4828.07 MB/s
Benchmark64XXFast/128-4           	50000000	        23.3 ns/op	5491.20 MB/s
Benchmark64XXFast/1024-4          	20000000	        98.8 ns/op	10359.89 MB/s
Benchmark64XXFast/8192-4          	 2000000	       680 ns/op	12031.62 MB/s
Benchmark64Fasthash/4-4           	200000000	         8.53 ns/op	 468.92 MB/s
Benchmark64Fasthash/8-4           	200000000	         6.51 ns/op	1228.47 MB/s
Benchmark64Fasthash/16-4          	200000000	         7.70 ns/op	2077.23 MB/s
Benchmark64Fasthash/32-4          	100000000	        11.2 ns/op	2861.64 MB/s
Benchmark64Fasthash/64-4          	100000000	        14.4 ns/op	4441.00 MB/s
Benchmark64Fasthash/96-4          	100000000	        19.6 ns/op	4908.43 MB/s
Benchmark64Fasthash/128-4         	50000000	        24.5 ns/op	5225.33 MB/s
Benchmark64Fasthash/1024-4        	10000000	       171 ns/op	5972.30 MB/s
Benchmark64Fasthash/8192-4        	 1000000	      1348 ns/op	6074.30 MB/s
Benchmark64Highway/4-4            	30000000	        37.8 ns/op	 105.93 MB/s
Benchmark64Highway/8-4            	30000000	        36.7 ns/op	 218.01 MB/s
Benchmark64Highway/16-4           	30000000	        35.2 ns/op	 455.05 MB/s
Benchmark64Highway/32-4           	50000000	        32.3 ns/op	 991.19 MB/s
Benchmark64Highway/64-4           	50000000	        35.3 ns/op	1812.60 MB/s
Benchmark64Highway/96-4           	30000000	        40.2 ns/op	2389.31 MB/s
Benchmark64Highway/128-4          	30000000	        42.7 ns/op	2996.53 MB/s
Benchmark64Highway/1024-4         	10000000	       153 ns/op	6683.62 MB/s
Benchmark64Highway/8192-4         	 1000000	      1165 ns/op	7031.05 MB/s
Benchmark64CRC64/4-4              	100000000	        13.5 ns/op	 295.28 MB/s
Benchmark64CRC64/8-4              	100000000	        20.1 ns/op	 398.89 MB/s
Benchmark64CRC64/16-4             	50000000	        35.9 ns/op	 445.88 MB/s
Benchmark64CRC64/32-4             	20000000	        71.8 ns/op	 445.77 MB/s
Benchmark64CRC64/64-4             	20000000	        59.9 ns/op	1068.25 MB/s
Benchmark64CRC64/96-4             	20000000	        79.2 ns/op	1212.63 MB/s
Benchmark64CRC64/128-4            	20000000	        95.7 ns/op	1338.08 MB/s
Benchmark64CRC64/1024-4           	 2000000	       652 ns/op	1568.57 MB/s
Benchmark64CRC64/8192-4           	  200000	      5081 ns/op	1612.18 MB/s
Benchmark64Sip13Hash/4-4          	100000000	        14.6 ns/op	 273.16 MB/s
Benchmark64Sip13Hash/8-4          	100000000	        15.1 ns/op	 530.44 MB/s
Benchmark64Sip13Hash/16-4         	100000000	        17.1 ns/op	 933.73 MB/s
Benchmark64Sip13Hash/32-4         	100000000	        20.9 ns/op	1532.43 MB/s
Benchmark64Sip13Hash/64-4         	50000000	        30.2 ns/op	2117.04 MB/s
Benchmark64Sip13Hash/96-4         	30000000	        37.3 ns/op	2573.09 MB/s
Benchmark64Sip13Hash/128-4        	30000000	        45.2 ns/op	2830.09 MB/s
Benchmark64Sip13Hash/1024-4       	 5000000	       278 ns/op	3677.40 MB/s
Benchmark64Sip13Hash/8192-4       	 1000000	      2135 ns/op	3836.78 MB/s
Benchmark64FNV1A/4-4              	50000000	        24.1 ns/op	 166.03 MB/s
Benchmark64FNV1A/8-4              	50000000	        27.1 ns/op	 295.05 MB/s
Benchmark64FNV1A/16-4             	30000000	        35.0 ns/op	 456.71 MB/s
Benchmark64FNV1A/32-4             	20000000	        53.9 ns/op	 593.31 MB/s
Benchmark64FNV1A/64-4             	20000000	        96.8 ns/op	 660.97 MB/s
Benchmark64FNV1A/96-4             	10000000	       141 ns/op	 677.27 MB/s
Benchmark64FNV1A/128-4            	10000000	       191 ns/op	 667.44 MB/s
Benchmark64FNV1A/1024-4           	 1000000	      1353 ns/op	 756.40 MB/s
Benchmark64FNV1A/8192-4           	  200000	     10718 ns/op	 764.30 MB/s
Benchmark64FNV1/4-4               	50000000	        24.4 ns/op	 163.63 MB/s
Benchmark64FNV1/8-4               	50000000	        26.9 ns/op	 297.44 MB/s
Benchmark64FNV1/16-4              	50000000	        37.4 ns/op	 427.26 MB/s
Benchmark64FNV1/32-4              	20000000	        58.2 ns/op	 549.51 MB/s
Benchmark64FNV1/64-4              	20000000	        94.6 ns/op	 676.41 MB/s
Benchmark64FNV1/96-4              	10000000	       141 ns/op	 679.83 MB/s
Benchmark64FNV1/128-4             	10000000	       182 ns/op	 700.19 MB/s
Benchmark64FNV1/1024-4            	 1000000	      1353 ns/op	 756.54 MB/s
Benchmark64FNV1/8192-4            	  200000	     10679 ns/op	 767.10 MB/s
Benchmark64T1ha/4-4               	100000000	        17.9 ns/op	 223.78 MB/s
Benchmark64T1ha/8-4               	100000000	        17.5 ns/op	 456.24 MB/s
Benchmark64T1ha/16-4              	50000000	        22.5 ns/op	 711.71 MB/s
Benchmark64T1ha/32-4              	50000000	        31.6 ns/op	1011.36 MB/s
Benchmark64T1ha/64-4              	100000000	        22.4 ns/op	2863.25 MB/s
Benchmark64T1ha/96-4              	50000000	        27.1 ns/op	3542.25 MB/s
Benchmark64T1ha/128-4             	50000000	        30.9 ns/op	4147.13 MB/s
Benchmark64T1ha/1024-4            	10000000	       150 ns/op	6789.50 MB/s
Benchmark64T1ha/8192-4            	 1000000	      1136 ns/op	7205.41 MB/s
Benchmark64Zaphod64/4-4           	100000000	        13.4 ns/op	 299.32 MB/s
Benchmark64Zaphod64/8-4           	100000000	        13.6 ns/op	 587.26 MB/s
Benchmark64Zaphod64/16-4          	100000000	        19.0 ns/op	 840.95 MB/s
Benchmark64Zaphod64/32-4          	50000000	        25.9 ns/op	1235.77 MB/s
Benchmark64Zaphod64/64-4          	30000000	        38.1 ns/op	1677.89 MB/s
Benchmark64Zaphod64/96-4          	30000000	        49.3 ns/op	1948.32 MB/s
Benchmark64Zaphod64/128-4         	20000000	        61.2 ns/op	2092.80 MB/s
Benchmark64Zaphod64/1024-4        	 3000000	       407 ns/op	2513.02 MB/s
Benchmark64Zaphod64/8192-4        	  500000	      3155 ns/op	2595.90 MB/s
Benchmark64Stadtx/4-4             	200000000	         9.01 ns/op	 443.88 MB/s
Benchmark64Stadtx/8-4             	100000000	        10.0 ns/op	 799.96 MB/s
Benchmark64Stadtx/16-4            	100000000	        11.3 ns/op	1417.13 MB/s
Benchmark64Stadtx/32-4            	100000000	        14.0 ns/op	2278.27 MB/s
Benchmark64Stadtx/64-4            	100000000	        18.6 ns/op	3442.64 MB/s
Benchmark64Stadtx/96-4            	100000000	        20.3 ns/op	4737.79 MB/s
Benchmark64Stadtx/128-4           	50000000	        24.5 ns/op	5223.67 MB/s
Benchmark64Stadtx/1024-4          	20000000	        94.1 ns/op	10884.76 MB/s
Benchmark64Stadtx/8192-4          	 2000000	       622 ns/op	13162.66 MB/s
Benchmark64Tsip/4-4               	200000000	         9.67 ns/op	 413.66 MB/s
Benchmark64Tsip/8-4               	200000000	         9.80 ns/op	 816.52 MB/s
Benchmark64Tsip/16-4              	100000000	        11.8 ns/op	1354.94 MB/s
Benchmark64Tsip/32-4              	100000000	        14.8 ns/op	2165.09 MB/s
Benchmark64Tsip/64-4              	50000000	        21.6 ns/op	2957.87 MB/s
Benchmark64Tsip/96-4              	50000000	        29.3 ns/op	3273.31 MB/s
Benchmark64Tsip/128-4             	50000000	        37.0 ns/op	3459.79 MB/s
Benchmark64Tsip/1024-4            	 5000000	       256 ns/op	3995.43 MB/s
Benchmark64Tsip/8192-4            	 1000000	      1980 ns/op	4136.33 MB/s
Benchmark64FarmHash/4-4           	100000000	        13.4 ns/op	 298.76 MB/s
Benchmark64FarmHash/8-4           	100000000	        14.2 ns/op	 564.80 MB/s
Benchmark64FarmHash/16-4          	100000000	        14.1 ns/op	1132.30 MB/s
Benchmark64FarmHash/32-4          	100000000	        18.6 ns/op	1724.59 MB/s
Benchmark64FarmHash/64-4          	50000000	        27.6 ns/op	2314.91 MB/s
Benchmark64FarmHash/96-4          	20000000	        76.6 ns/op	1253.81 MB/s
Benchmark64FarmHash/128-4         	20000000	        73.2 ns/op	1748.69 MB/s
Benchmark64FarmHash/1024-4        	 3000000	       493 ns/op	2077.06 MB/s
Benchmark64FarmHash/8192-4        	  300000	      3879 ns/op	2111.80 MB/s

```

# Conclusion
Don' conclude on my testresults, you should test on your own hardware with disabled cpu governor. Some implementations are optimized for specific cpus and some cpus have temperature based overclocking and downclocking, keep this in mind when doing benchmarks.


# Contribution
I'm happy about your testresults and PR with additional hashtests

# TODO
describe collisionpossibility
