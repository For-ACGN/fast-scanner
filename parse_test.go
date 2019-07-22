package Scanner

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func ExampleParseTarget() {
	testdata := []string{
		"192.168.1.1",
		"192.168.1.1,192.168.1.2",
		"192.168.1.1, 192.168.1.2",
	}
	for _, str := range testdata {
		fmt.Println(ParseTarget(str))
	}
	// Output:
	// [192.168.1.1]
	// [192.168.1.1 192.168.1.2]
	// [192.168.1.1 192.168.1.2]
}

func TestGenIPWithHyphen(t *testing.T) {
	expected := `0.0.0.1
0.0.0.1
0.0.0.2
0.0.0.3
0.0.0.4
0.0.0.5
0.0.0.6
0.0.0.7
0.0.0.8
0.0.0.9
0.0.0.10
0.0.0.11
0.0.0.12
0.0.0.13
0.0.0.14
0.0.0.15
0.0.0.16
0.0.0.17
0.0.0.18
0.0.0.19
0.0.0.20
0.0.0.21
0.0.0.22
0.0.0.23
0.0.0.24
0.0.0.25
0.0.0.26
0.0.0.27
0.0.0.28
0.0.0.29
0.0.0.30
0.0.0.31
0.0.0.32
0.0.0.33
0.0.0.34
0.0.0.35
0.0.0.36
0.0.0.37
0.0.0.38
0.0.0.39
0.0.0.40
0.0.0.41
0.0.0.42
0.0.0.43
0.0.0.44
0.0.0.45
0.0.0.46
0.0.0.47
0.0.0.48
0.0.0.49
0.0.0.50
0.0.0.51
0.0.0.52
0.0.0.53
0.0.0.54
0.0.0.55
0.0.0.56
0.0.0.57
0.0.0.58
0.0.0.59
0.0.0.60
0.0.0.61
0.0.0.62
0.0.0.63
0.0.0.64
0.0.0.65
0.0.0.66
0.0.0.67
0.0.0.68
0.0.0.69
0.0.0.70
0.0.0.71
0.0.0.72
0.0.0.73
0.0.0.74
0.0.0.75
0.0.0.76
0.0.0.77
0.0.0.78
0.0.0.79
0.0.0.80
0.0.0.81
0.0.0.82
0.0.0.83
0.0.0.84
0.0.0.85
0.0.0.86
0.0.0.87
0.0.0.88
0.0.0.89
0.0.0.90
0.0.0.91
0.0.0.92
0.0.0.93
0.0.0.94
0.0.0.95
0.0.0.96
0.0.0.97
0.0.0.98
0.0.0.99
0.0.0.100
0.0.0.101
0.0.0.102
0.0.0.103
0.0.0.104
0.0.0.105
0.0.0.106
0.0.0.107
0.0.0.108
0.0.0.109
0.0.0.110
0.0.0.111
0.0.0.112
0.0.0.113
0.0.0.114
0.0.0.115
0.0.0.116
0.0.0.117
0.0.0.118
0.0.0.119
0.0.0.120
0.0.0.121
0.0.0.122
0.0.0.123
0.0.0.124
0.0.0.125
0.0.0.126
0.0.0.127
0.0.0.128
0.0.0.129
0.0.0.130
0.0.0.131
0.0.0.132
0.0.0.133
0.0.0.134
0.0.0.135
0.0.0.136
0.0.0.137
0.0.0.138
0.0.0.139
0.0.0.140
0.0.0.141
0.0.0.142
0.0.0.143
0.0.0.144
0.0.0.145
0.0.0.146
0.0.0.147
0.0.0.148
0.0.0.149
0.0.0.150
0.0.0.151
0.0.0.152
0.0.0.153
0.0.0.154
0.0.0.155
0.0.0.156
0.0.0.157
0.0.0.158
0.0.0.159
0.0.0.160
0.0.0.161
0.0.0.162
0.0.0.163
0.0.0.164
0.0.0.165
0.0.0.166
0.0.0.167
0.0.0.168
0.0.0.169
0.0.0.170
0.0.0.171
0.0.0.172
0.0.0.173
0.0.0.174
0.0.0.175
0.0.0.176
0.0.0.177
0.0.0.178
0.0.0.179
0.0.0.180
0.0.0.181
0.0.0.182
0.0.0.183
0.0.0.184
0.0.0.185
0.0.0.186
0.0.0.187
0.0.0.188
0.0.0.189
0.0.0.190
0.0.0.191
0.0.0.192
0.0.0.193
0.0.0.194
0.0.0.195
0.0.0.196
0.0.0.197
0.0.0.198
0.0.0.199
0.0.0.200
0.0.0.201
0.0.0.202
0.0.0.203
0.0.0.204
0.0.0.205
0.0.0.206
0.0.0.207
0.0.0.208
0.0.0.209
0.0.0.210
0.0.0.211
0.0.0.212
0.0.0.213
0.0.0.214
0.0.0.215
0.0.0.216
0.0.0.217
0.0.0.218
0.0.0.219
0.0.0.220
0.0.0.221
0.0.0.222
0.0.0.223
0.0.0.224
0.0.0.225
0.0.0.226
0.0.0.227
0.0.0.228
0.0.0.229
0.0.0.230
0.0.0.231
0.0.0.232
0.0.0.233
0.0.0.234
0.0.0.235
0.0.0.236
0.0.0.237
0.0.0.238
0.0.0.239
0.0.0.240
0.0.0.241
0.0.0.242
0.0.0.243
0.0.0.244
0.0.0.245
0.0.0.246
0.0.0.247
0.0.0.248
0.0.0.249
0.0.0.250
0.0.0.251
0.0.0.252
0.0.0.253
0.0.0.254
0.0.0.255
0.0.1.0
::1
::1
::2
::3
::4
::5
::6
::7
::8
::9
::a
::b
::c
::d
::e
::f
::10
::11
::12
::13
::14
::15
::16
::17
::18
::19
::1a
::1b
::1c
::1d
::1e
::1f
::20
::21
::22
::23
::24
::25
::26
::27
::28
::29
::2a
::2b
::2c
::2d
::2e
::2f
::30
::31
::32
::33
::34
::35
::36
::37
::38
::39
::3a
::3b
::3c
::3d
::3e
::3f
::40
::41
::42
::43
::44
::45
::46
::47
::48
::49
::4a
::4b
::4c
::4d
::4e
::4f
::50
::51
::52
::53
::54
::55
::56
::57
::58
::59
::5a
::5b
::5c
::5d
::5e
::5f
::60
::61
::62
::63
::64
::65
::66
::67
::68
::69
::6a
::6b
::6c
::6d
::6e
::6f
::70
::71
::72
::73
::74
::75
::76
::77
::78
::79
::7a
::7b
::7c
::7d
::7e
::7f
::80
::81
::82
::83
::84
::85
::86
::87
::88
::89
::8a
::8b
::8c
::8d
::8e
::8f
::90
::91
::92
::93
::94
::95
::96
::97
::98
::99
::9a
::9b
::9c
::9d
::9e
::9f
::a0
::a1
::a2
::a3
::a4
::a5
::a6
::a7
::a8
::a9
::aa
::ab
::ac
::ad
::ae
::af
::b0
::b1
::b2
::b3
::b4
::b5
::b6
::b7
::b8
::b9
::ba
::bb
::bc
::bd
::be
::bf
::c0
::c1
::c2
::c3
::c4
::c5
::c6
::c7
::c8
::c9
::ca
::cb
::cc
::cd
::ce
::cf
::d0
::d1
::d2
::d3
::d4
::d5
::d6
::d7
::d8
::d9
::da
::db
::dc
::dd
::de
::df
::e0
::e1
::e2
::e3
::e4
::e5
::e6
::e7
::e8
::e9
::ea
::eb
::ec
::ed
::ee
::ef
::f0
::f1
::f2
::f3
::f4
::f5
::f6
::f7
::f8
::f9
::fa
::fb
::fc
::fd
::fe
::ff
::100
fe80::1
fe80::2
fe80::3
fe80::4
fe80::5
fe80::6
fe80::7
fe80::8
fe80::9
fe80::a
fe80::b
fe80::c
fe80::d
fe80::e
fe80::f
fe80::10
`
	ipChan := make(chan net.IP, 1)
	ctx := context.Background()
	go func() {
		genIPWithHyphen(ctx, ipChan, "0.0.0.1-0.0.0.1")
		genIPWithHyphen(ctx, ipChan, "0.0.0.1-0.0.1.0")
		genIPWithHyphen(ctx, ipChan, "::1-::1")
		genIPWithHyphen(ctx, ipChan, "::1-::100") // 1 byte -> 2 bytes
		genIPWithHyphen(ctx, ipChan, "fe80::1-fe80::10")
		close(ipChan)
	}()
	b := &bytes.Buffer{}
	for ip := range ipChan {
		_, _ = fmt.Fprintln(b, ip)
	}
	require.Equal(t, expected, b.String())
}

func TestGenIPWithDash(t *testing.T) {
	expected := `192.168.1.254
192.168.1.255
192.168.1.244
192.168.1.0
192.168.1.1
192.168.1.2
192.168.1.3
192.168.1.4
192.168.1.5
192.168.1.6
192.168.1.7
192.168.1.8
192.168.1.9
192.168.1.10
192.168.1.11
192.168.1.12
192.168.1.13
192.168.1.14
192.168.1.15
fe80::0
fe80::1
::1
`
	ipChan := make(chan net.IP, 1)
	ctx := context.Background()
	go func() {
		genIPWithDash(ctx, ipChan, "192.168.1.255/31")
		genIPWithDash(ctx, ipChan, "192.168.1.244/32")
		genIPWithDash(ctx, ipChan, "192.168.1.1/28")
		// genIPWithDash(ctx, ipChan, "fe80::0/127")
		// genIPWithDash(ctx, ipChan, "::1/128")
		close(ipChan)
	}()
	b := &bytes.Buffer{}
	for ip := range ipChan {
		_, _ = fmt.Fprintln(b, ip)
	}
	require.Equal(t, expected, b.String())

	ip, ipnet, _ := net.ParseCIDR("fe80::1/127")
	fmt.Println(ip, ipnet, ipnet.IP, ipnet.Mask)

}
