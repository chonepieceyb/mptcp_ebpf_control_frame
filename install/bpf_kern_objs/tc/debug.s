
tc_egress.c.o:	file format ELF64-BPF


Disassembly of section classifier:

0000000000000000 tc_egress_main:
; __section("classifier") int tc_egress_main(struct __sk_buff *skb) {
       0:	r6 = r1
;     void *data_end = (void *)(__u64)(skb->data_end);
       1:	r2 = *(u32 *)(r6 + 80)
;     void *data = (void *)(__u64)(skb->data);
       2:	r7 = *(u32 *)(r6 + 76)
;     CHECK_BOUND(eth, data_end);
       3:	r1 = r7
       4:	r1 += 14
       5:	if r1 > r2 goto +1209 <LBB0_330>
;     return eth->h_proto; /* network-byte-order */
       6:	r1 = *(u8 *)(r7 + 12)
       7:	r3 = *(u8 *)(r7 + 13)
       8:	r3 <<= 8
       9:	r3 |= r1
;     if (res != bpf_htons(ETH_P_IP)) {
      10:	if r3 != 8 goto +1204 <LBB0_330>
;     CHECK_BOUND(iph, data_end);
      11:	r1 = r7
      12:	r1 += 34
      13:	if r1 > r2 goto +1201 <LBB0_330>
;     int hl = iph->ihl << 2;  
      14:	r1 = *(u8 *)(r7 + 14)
      15:	r1 &= 15
;     if (hl != 20) {
      16:	if r1 != 5 goto +1198 <LBB0_330>
;     return iph->protocol;
      17:	r1 = *(u8 *)(r7 + 23)
;     if (res != IPPROTO_TCP) {
      18:	if r1 != 6 goto +1196 <LBB0_330>
;     CHECK_BOUND(tcph, data_end);
      19:	r4 = r7
      20:	r4 += 54
      21:	if r4 > r2 goto +1193 <LBB0_330>
;     int hlen = tcph->doff;
      22:	r1 = *(u16 *)(r7 + 46)
;     return hlen << 2;  //不知道直接获取对不对，先这样
      23:	r3 = r1
      24:	r3 >>= 2
      25:	r3 &= 60
      26:	r5 = 21
;     if (res <= 20) {
      27:	if r5 > r3 goto +1187 <LBB0_330>
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
      28:	r5 = r7
      29:	r5 += 57
;         if (curr_idx >= tcp_opt_len) return;
      30:	if r5 > r2 goto +1184 <LBB0_330>
      31:	r3 += -20
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
      32:	r5 = *(u8 *)(r4 + 0)
      33:	r0 = 2
      34:	if r0 > r5 goto +10 <LBB0_11>
      35:	if r5 == 30 goto +1 <LBB0_10>
      36:	goto +12 <LBB0_12>

0000000000000128 LBB0_10:
;         pos += opt->len;
      37:	r0 = *(u8 *)(r7 + 55)
      38:	r5 = r4
      39:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
      40:	r0 = *(u8 *)(r7 + 56)
      41:	r0 >>= 4
      42:	r8 = 1
      43:	r8 <<= r0
      44:	goto +8 <LBB0_13>

0000000000000168 LBB0_11:
      45:	r8 = 0
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
      46:	r5 = r7
      47:	r5 += 55
      48:	goto +4 <LBB0_13>

0000000000000188 LBB0_12:
      49:	r0 = *(u8 *)(r7 + 55)
      50:	r5 = r4
      51:	r5 += r0
      52:	r8 = 0

00000000000001a8 LBB0_13:
;         int curr_idx = pos - start;
      53:	r0 = r5
      54:	r0 -= r4
      55:	r0 <<= 32
      56:	r9 = r0
      57:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
      58:	if r9 s>= r3 goto +1113 <LBB0_322>
;         int curr_idx = pos - start;
      59:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
      60:	if r0 != 1 goto +21 <LBB0_21>
      61:	r0 = r5
      62:	r0 += 3
      63:	if r0 > r2 goto +1108 <LBB0_322>
      64:	r0 = *(u8 *)(r5 + 0)
      65:	r9 = 2
      66:	if r9 > r0 goto +11 <LBB0_19>
      67:	if r0 == 30 goto +1 <LBB0_18>
      68:	goto +11 <LBB0_20>

0000000000000228 LBB0_18:
;         pos += opt->len;
      69:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
      70:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
      71:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
      72:	r9 >>= 4
      73:	r0 = 1
      74:	r0 <<= r9
      75:	r0 |= r8
      76:	r8 = r0
      77:	goto +4 <LBB0_21>

0000000000000270 LBB0_19:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
      78:	r5 += 1
      79:	goto +2 <LBB0_21>

0000000000000280 LBB0_20:
      80:	r0 = *(u8 *)(r5 + 1)
      81:	r5 += r0

0000000000000290 LBB0_21:
;         int curr_idx = pos - start;
      82:	r0 = r5
      83:	r0 -= r4
      84:	r0 <<= 32
      85:	r9 = r0
      86:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
      87:	if r9 s>= r3 goto +1084 <LBB0_322>
;         int curr_idx = pos - start;
      88:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
      89:	if r0 != 2 goto +21 <LBB0_29>
      90:	r0 = r5
      91:	r0 += 3
      92:	if r0 > r2 goto +1079 <LBB0_322>
      93:	r0 = *(u8 *)(r5 + 0)
      94:	r9 = 2
      95:	if r9 > r0 goto +11 <LBB0_27>
      96:	if r0 == 30 goto +1 <LBB0_26>
      97:	goto +11 <LBB0_28>

0000000000000310 LBB0_26:
;         pos += opt->len;
      98:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
      99:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
     100:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
     101:	r9 >>= 4
     102:	r0 = 1
     103:	r0 <<= r9
     104:	r0 |= r8
     105:	r8 = r0
     106:	goto +4 <LBB0_29>

0000000000000358 LBB0_27:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     107:	r5 += 1
     108:	goto +2 <LBB0_29>

0000000000000368 LBB0_28:
     109:	r0 = *(u8 *)(r5 + 1)
     110:	r5 += r0

0000000000000378 LBB0_29:
;         int curr_idx = pos - start;
     111:	r0 = r5
     112:	r0 -= r4
     113:	r0 <<= 32
     114:	r9 = r0
     115:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
     116:	if r9 s>= r3 goto +1055 <LBB0_322>
;         int curr_idx = pos - start;
     117:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     118:	if r0 != 3 goto +21 <LBB0_37>
     119:	r0 = r5
     120:	r0 += 3
     121:	if r0 > r2 goto +1050 <LBB0_322>
     122:	r0 = *(u8 *)(r5 + 0)
     123:	r9 = 2
     124:	if r9 > r0 goto +11 <LBB0_35>
     125:	if r0 == 30 goto +1 <LBB0_34>
     126:	goto +11 <LBB0_36>

00000000000003f8 LBB0_34:
;         pos += opt->len;
     127:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
     128:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
     129:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
     130:	r9 >>= 4
     131:	r0 = 1
     132:	r0 <<= r9
     133:	r0 |= r8
     134:	r8 = r0
     135:	goto +4 <LBB0_37>

0000000000000440 LBB0_35:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     136:	r5 += 1
     137:	goto +2 <LBB0_37>

0000000000000450 LBB0_36:
     138:	r0 = *(u8 *)(r5 + 1)
     139:	r5 += r0

0000000000000460 LBB0_37:
;         int curr_idx = pos - start;
     140:	r0 = r5
     141:	r0 -= r4
     142:	r0 <<= 32
     143:	r9 = r0
     144:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
     145:	if r9 s>= r3 goto +1026 <LBB0_322>
;         int curr_idx = pos - start;
     146:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     147:	if r0 != 4 goto +21 <LBB0_45>
     148:	r0 = r5
     149:	r0 += 3
     150:	if r0 > r2 goto +1021 <LBB0_322>
     151:	r0 = *(u8 *)(r5 + 0)
     152:	r9 = 2
     153:	if r9 > r0 goto +11 <LBB0_43>
     154:	if r0 == 30 goto +1 <LBB0_42>
     155:	goto +11 <LBB0_44>

00000000000004e0 LBB0_42:
;         pos += opt->len;
     156:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
     157:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
     158:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
     159:	r9 >>= 4
     160:	r0 = 1
     161:	r0 <<= r9
     162:	r0 |= r8
     163:	r8 = r0
     164:	goto +4 <LBB0_45>

0000000000000528 LBB0_43:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     165:	r5 += 1
     166:	goto +2 <LBB0_45>

0000000000000538 LBB0_44:
     167:	r0 = *(u8 *)(r5 + 1)
     168:	r5 += r0

0000000000000548 LBB0_45:
;         int curr_idx = pos - start;
     169:	r0 = r5
     170:	r0 -= r4
     171:	r0 <<= 32
     172:	r9 = r0
     173:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
     174:	if r9 s>= r3 goto +997 <LBB0_322>
;         int curr_idx = pos - start;
     175:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     176:	if r0 != 5 goto +21 <LBB0_53>
     177:	r0 = r5
     178:	r0 += 3
     179:	if r0 > r2 goto +992 <LBB0_322>
     180:	r0 = *(u8 *)(r5 + 0)
     181:	r9 = 2
     182:	if r9 > r0 goto +11 <LBB0_51>
     183:	if r0 == 30 goto +1 <LBB0_50>
     184:	goto +11 <LBB0_52>

00000000000005c8 LBB0_50:
;         pos += opt->len;
     185:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
     186:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
     187:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
     188:	r9 >>= 4
     189:	r0 = 1
     190:	r0 <<= r9
     191:	r0 |= r8
     192:	r8 = r0
     193:	goto +4 <LBB0_53>

0000000000000610 LBB0_51:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     194:	r5 += 1
     195:	goto +2 <LBB0_53>

0000000000000620 LBB0_52:
     196:	r0 = *(u8 *)(r5 + 1)
     197:	r5 += r0

0000000000000630 LBB0_53:
;         int curr_idx = pos - start;
     198:	r0 = r5
     199:	r0 -= r4
     200:	r0 <<= 32
     201:	r9 = r0
     202:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
     203:	if r9 s>= r3 goto +968 <LBB0_322>
;         int curr_idx = pos - start;
     204:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     205:	if r0 != 6 goto +21 <LBB0_61>
     206:	r0 = r5
     207:	r0 += 3
     208:	if r0 > r2 goto +963 <LBB0_322>
     209:	r0 = *(u8 *)(r5 + 0)
     210:	r9 = 2
     211:	if r9 > r0 goto +11 <LBB0_59>
     212:	if r0 == 30 goto +1 <LBB0_58>
     213:	goto +11 <LBB0_60>

00000000000006b0 LBB0_58:
;         pos += opt->len;
     214:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
     215:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
     216:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
     217:	r9 >>= 4
     218:	r0 = 1
     219:	r0 <<= r9
     220:	r0 |= r8
     221:	r8 = r0
     222:	goto +4 <LBB0_61>

00000000000006f8 LBB0_59:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     223:	r5 += 1
     224:	goto +2 <LBB0_61>

0000000000000708 LBB0_60:
     225:	r0 = *(u8 *)(r5 + 1)
     226:	r5 += r0

0000000000000718 LBB0_61:
;         int curr_idx = pos - start;
     227:	r0 = r5
     228:	r0 -= r4
     229:	r0 <<= 32
     230:	r9 = r0
     231:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
     232:	if r9 s>= r3 goto +939 <LBB0_322>
;         int curr_idx = pos - start;
     233:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     234:	if r0 != 7 goto +21 <LBB0_69>
     235:	r0 = r5
     236:	r0 += 3
     237:	if r0 > r2 goto +934 <LBB0_322>
     238:	r0 = *(u8 *)(r5 + 0)
     239:	r9 = 2
     240:	if r9 > r0 goto +11 <LBB0_67>
     241:	if r0 == 30 goto +1 <LBB0_66>
     242:	goto +11 <LBB0_68>

0000000000000798 LBB0_66:
;         pos += opt->len;
     243:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
     244:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
     245:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
     246:	r9 >>= 4
     247:	r0 = 1
     248:	r0 <<= r9
     249:	r0 |= r8
     250:	r8 = r0
     251:	goto +4 <LBB0_69>

00000000000007e0 LBB0_67:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     252:	r5 += 1
     253:	goto +2 <LBB0_69>

00000000000007f0 LBB0_68:
     254:	r0 = *(u8 *)(r5 + 1)
     255:	r5 += r0

0000000000000800 LBB0_69:
;         int curr_idx = pos - start;
     256:	r0 = r5
     257:	r0 -= r4
     258:	r0 <<= 32
     259:	r9 = r0
     260:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
     261:	if r9 s>= r3 goto +910 <LBB0_322>
;         int curr_idx = pos - start;
     262:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     263:	if r0 != 8 goto +21 <LBB0_77>
     264:	r0 = r5
     265:	r0 += 3
     266:	if r0 > r2 goto +905 <LBB0_322>
     267:	r0 = *(u8 *)(r5 + 0)
     268:	r9 = 2
     269:	if r9 > r0 goto +11 <LBB0_75>
     270:	if r0 == 30 goto +1 <LBB0_74>
     271:	goto +11 <LBB0_76>

0000000000000880 LBB0_74:
;         pos += opt->len;
     272:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
     273:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
     274:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
     275:	r9 >>= 4
     276:	r0 = 1
     277:	r0 <<= r9
     278:	r0 |= r8
     279:	r8 = r0
     280:	goto +4 <LBB0_77>

00000000000008c8 LBB0_75:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     281:	r5 += 1
     282:	goto +2 <LBB0_77>

00000000000008d8 LBB0_76:
     283:	r0 = *(u8 *)(r5 + 1)
     284:	r5 += r0

00000000000008e8 LBB0_77:
;         int curr_idx = pos - start;
     285:	r0 = r5
     286:	r0 -= r4
     287:	r0 <<= 32
     288:	r9 = r0
     289:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
     290:	if r9 s>= r3 goto +881 <LBB0_322>
;         int curr_idx = pos - start;
     291:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     292:	if r0 != 9 goto +21 <LBB0_85>
     293:	r0 = r5
     294:	r0 += 3
     295:	if r0 > r2 goto +876 <LBB0_322>
     296:	r0 = *(u8 *)(r5 + 0)
     297:	r9 = 2
     298:	if r9 > r0 goto +11 <LBB0_83>
     299:	if r0 == 30 goto +1 <LBB0_82>
     300:	goto +11 <LBB0_84>

0000000000000968 LBB0_82:
;         pos += opt->len;
     301:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
     302:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
     303:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
     304:	r9 >>= 4
     305:	r0 = 1
     306:	r0 <<= r9
     307:	r0 |= r8
     308:	r8 = r0
     309:	goto +4 <LBB0_85>

00000000000009b0 LBB0_83:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     310:	r5 += 1
     311:	goto +2 <LBB0_85>

00000000000009c0 LBB0_84:
     312:	r0 = *(u8 *)(r5 + 1)
     313:	r5 += r0

00000000000009d0 LBB0_85:
;         int curr_idx = pos - start;
     314:	r0 = r5
     315:	r0 -= r4
     316:	r0 <<= 32
     317:	r9 = r0
     318:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
     319:	if r9 s>= r3 goto +852 <LBB0_322>
;         int curr_idx = pos - start;
     320:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     321:	if r0 != 10 goto +21 <LBB0_93>
     322:	r0 = r5
     323:	r0 += 3
     324:	if r0 > r2 goto +847 <LBB0_322>
     325:	r0 = *(u8 *)(r5 + 0)
     326:	r9 = 2
     327:	if r9 > r0 goto +11 <LBB0_91>
     328:	if r0 == 30 goto +1 <LBB0_90>
     329:	goto +11 <LBB0_92>

0000000000000a50 LBB0_90:
;         pos += opt->len;
     330:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
     331:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
     332:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
     333:	r9 >>= 4
     334:	r0 = 1
     335:	r0 <<= r9
     336:	r0 |= r8
     337:	r8 = r0
     338:	goto +4 <LBB0_93>

0000000000000a98 LBB0_91:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     339:	r5 += 1
     340:	goto +2 <LBB0_93>

0000000000000aa8 LBB0_92:
     341:	r0 = *(u8 *)(r5 + 1)
     342:	r5 += r0

0000000000000ab8 LBB0_93:
;         int curr_idx = pos - start;
     343:	r0 = r5
     344:	r0 -= r4
     345:	r0 <<= 32
     346:	r9 = r0
     347:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
     348:	if r9 s>= r3 goto +823 <LBB0_322>
;         int curr_idx = pos - start;
     349:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     350:	if r0 != 11 goto +21 <LBB0_101>
     351:	r0 = r5
     352:	r0 += 3
     353:	if r0 > r2 goto +818 <LBB0_322>
     354:	r0 = *(u8 *)(r5 + 0)
     355:	r9 = 2
     356:	if r9 > r0 goto +11 <LBB0_99>
     357:	if r0 == 30 goto +1 <LBB0_98>
     358:	goto +11 <LBB0_100>

0000000000000b38 LBB0_98:
;         pos += opt->len;
     359:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
     360:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
     361:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
     362:	r9 >>= 4
     363:	r0 = 1
     364:	r0 <<= r9
     365:	r0 |= r8
     366:	r8 = r0
     367:	goto +4 <LBB0_101>

0000000000000b80 LBB0_99:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     368:	r5 += 1
     369:	goto +2 <LBB0_101>

0000000000000b90 LBB0_100:
     370:	r0 = *(u8 *)(r5 + 1)
     371:	r5 += r0

0000000000000ba0 LBB0_101:
;         int curr_idx = pos - start;
     372:	r0 = r5
     373:	r0 -= r4
     374:	r0 <<= 32
     375:	r9 = r0
     376:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
     377:	if r9 s>= r3 goto +794 <LBB0_322>
;         int curr_idx = pos - start;
     378:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     379:	if r0 != 12 goto +21 <LBB0_109>
     380:	r0 = r5
     381:	r0 += 3
     382:	if r0 > r2 goto +789 <LBB0_322>
     383:	r0 = *(u8 *)(r5 + 0)
     384:	r9 = 2
     385:	if r9 > r0 goto +11 <LBB0_107>
     386:	if r0 == 30 goto +1 <LBB0_106>
     387:	goto +11 <LBB0_108>

0000000000000c20 LBB0_106:
;         pos += opt->len;
     388:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
     389:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
     390:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
     391:	r9 >>= 4
     392:	r0 = 1
     393:	r0 <<= r9
     394:	r0 |= r8
     395:	r8 = r0
     396:	goto +4 <LBB0_109>

0000000000000c68 LBB0_107:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     397:	r5 += 1
     398:	goto +2 <LBB0_109>

0000000000000c78 LBB0_108:
     399:	r0 = *(u8 *)(r5 + 1)
     400:	r5 += r0

0000000000000c88 LBB0_109:
;         int curr_idx = pos - start;
     401:	r0 = r5
     402:	r0 -= r4
     403:	r0 <<= 32
     404:	r9 = r0
     405:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
     406:	if r9 s>= r3 goto +765 <LBB0_322>
;         int curr_idx = pos - start;
     407:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     408:	if r0 != 13 goto +21 <LBB0_117>
     409:	r0 = r5
     410:	r0 += 3
     411:	if r0 > r2 goto +760 <LBB0_322>
     412:	r0 = *(u8 *)(r5 + 0)
     413:	r9 = 2
     414:	if r9 > r0 goto +11 <LBB0_115>
     415:	if r0 == 30 goto +1 <LBB0_114>
     416:	goto +11 <LBB0_116>

0000000000000d08 LBB0_114:
;         pos += opt->len;
     417:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
     418:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
     419:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
     420:	r9 >>= 4
     421:	r0 = 1
     422:	r0 <<= r9
     423:	r0 |= r8
     424:	r8 = r0
     425:	goto +4 <LBB0_117>

0000000000000d50 LBB0_115:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     426:	r5 += 1
     427:	goto +2 <LBB0_117>

0000000000000d60 LBB0_116:
     428:	r0 = *(u8 *)(r5 + 1)
     429:	r5 += r0

0000000000000d70 LBB0_117:
;         int curr_idx = pos - start;
     430:	r0 = r5
     431:	r0 -= r4
     432:	r0 <<= 32
     433:	r9 = r0
     434:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
     435:	if r9 s>= r3 goto +736 <LBB0_322>
;         int curr_idx = pos - start;
     436:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     437:	if r0 != 14 goto +21 <LBB0_125>
     438:	r0 = r5
     439:	r0 += 3
     440:	if r0 > r2 goto +731 <LBB0_322>
     441:	r0 = *(u8 *)(r5 + 0)
     442:	r9 = 2
     443:	if r9 > r0 goto +11 <LBB0_123>
     444:	if r0 == 30 goto +1 <LBB0_122>
     445:	goto +11 <LBB0_124>

0000000000000df0 LBB0_122:
;         pos += opt->len;
     446:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
     447:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
     448:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
     449:	r9 >>= 4
     450:	r0 = 1
     451:	r0 <<= r9
     452:	r0 |= r8
     453:	r8 = r0
     454:	goto +4 <LBB0_125>

0000000000000e38 LBB0_123:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     455:	r5 += 1
     456:	goto +2 <LBB0_125>

0000000000000e48 LBB0_124:
     457:	r0 = *(u8 *)(r5 + 1)
     458:	r5 += r0

0000000000000e58 LBB0_125:
;         int curr_idx = pos - start;
     459:	r0 = r5
     460:	r0 -= r4
     461:	r0 <<= 32
     462:	r9 = r0
     463:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
     464:	if r9 s>= r3 goto +707 <LBB0_322>
;         int curr_idx = pos - start;
     465:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     466:	if r0 != 15 goto +21 <LBB0_133>
     467:	r0 = r5
     468:	r0 += 3
     469:	if r0 > r2 goto +702 <LBB0_322>
     470:	r0 = *(u8 *)(r5 + 0)
     471:	r9 = 2
     472:	if r9 > r0 goto +11 <LBB0_131>
     473:	if r0 == 30 goto +1 <LBB0_130>
     474:	goto +11 <LBB0_132>

0000000000000ed8 LBB0_130:
;         pos += opt->len;
     475:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
     476:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
     477:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
     478:	r9 >>= 4
     479:	r0 = 1
     480:	r0 <<= r9
     481:	r0 |= r8
     482:	r8 = r0
     483:	goto +4 <LBB0_133>

0000000000000f20 LBB0_131:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     484:	r5 += 1
     485:	goto +2 <LBB0_133>

0000000000000f30 LBB0_132:
     486:	r0 = *(u8 *)(r5 + 1)
     487:	r5 += r0

0000000000000f40 LBB0_133:
;         int curr_idx = pos - start;
     488:	r0 = r5
     489:	r0 -= r4
     490:	r0 <<= 32
     491:	r9 = r0
     492:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
     493:	if r9 s>= r3 goto +678 <LBB0_322>
;         int curr_idx = pos - start;
     494:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     495:	if r0 != 16 goto +21 <LBB0_141>
     496:	r0 = r5
     497:	r0 += 3
     498:	if r0 > r2 goto +673 <LBB0_322>
     499:	r0 = *(u8 *)(r5 + 0)
     500:	r9 = 2
     501:	if r9 > r0 goto +11 <LBB0_139>
     502:	if r0 == 30 goto +1 <LBB0_138>
     503:	goto +11 <LBB0_140>

0000000000000fc0 LBB0_138:
;         pos += opt->len;
     504:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
     505:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
     506:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
     507:	r9 >>= 4
     508:	r0 = 1
     509:	r0 <<= r9
     510:	r0 |= r8
     511:	r8 = r0
     512:	goto +4 <LBB0_141>

0000000000001008 LBB0_139:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     513:	r5 += 1
     514:	goto +2 <LBB0_141>

0000000000001018 LBB0_140:
     515:	r0 = *(u8 *)(r5 + 1)
     516:	r5 += r0

0000000000001028 LBB0_141:
;         int curr_idx = pos - start;
     517:	r0 = r5
     518:	r0 -= r4
     519:	r0 <<= 32
     520:	r9 = r0
     521:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
     522:	if r9 s>= r3 goto +649 <LBB0_322>
;         int curr_idx = pos - start;
     523:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     524:	if r0 != 17 goto +21 <LBB0_149>
     525:	r0 = r5
     526:	r0 += 3
     527:	if r0 > r2 goto +644 <LBB0_322>
     528:	r0 = *(u8 *)(r5 + 0)
     529:	r9 = 2
     530:	if r9 > r0 goto +11 <LBB0_147>
     531:	if r0 == 30 goto +1 <LBB0_146>
     532:	goto +11 <LBB0_148>

00000000000010a8 LBB0_146:
;         pos += opt->len;
     533:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
     534:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
     535:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
     536:	r9 >>= 4
     537:	r0 = 1
     538:	r0 <<= r9
     539:	r0 |= r8
     540:	r8 = r0
     541:	goto +4 <LBB0_149>

00000000000010f0 LBB0_147:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     542:	r5 += 1
     543:	goto +2 <LBB0_149>

0000000000001100 LBB0_148:
     544:	r0 = *(u8 *)(r5 + 1)
     545:	r5 += r0

0000000000001110 LBB0_149:
;         int curr_idx = pos - start;
     546:	r0 = r5
     547:	r0 -= r4
     548:	r0 <<= 32
     549:	r9 = r0
     550:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
     551:	if r9 s>= r3 goto +620 <LBB0_322>
;         int curr_idx = pos - start;
     552:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     553:	if r0 != 18 goto +21 <LBB0_157>
     554:	r0 = r5
     555:	r0 += 3
     556:	if r0 > r2 goto +615 <LBB0_322>
     557:	r0 = *(u8 *)(r5 + 0)
     558:	r9 = 2
     559:	if r9 > r0 goto +11 <LBB0_155>
     560:	if r0 == 30 goto +1 <LBB0_154>
     561:	goto +11 <LBB0_156>

0000000000001190 LBB0_154:
;         pos += opt->len;
     562:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
     563:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
     564:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
     565:	r9 >>= 4
     566:	r0 = 1
     567:	r0 <<= r9
     568:	r0 |= r8
     569:	r8 = r0
     570:	goto +4 <LBB0_157>

00000000000011d8 LBB0_155:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     571:	r5 += 1
     572:	goto +2 <LBB0_157>

00000000000011e8 LBB0_156:
     573:	r0 = *(u8 *)(r5 + 1)
     574:	r5 += r0

00000000000011f8 LBB0_157:
;         int curr_idx = pos - start;
     575:	r0 = r5
     576:	r0 -= r4
     577:	r0 <<= 32
     578:	r9 = r0
     579:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
     580:	if r9 s>= r3 goto +591 <LBB0_322>
;         int curr_idx = pos - start;
     581:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     582:	if r0 != 19 goto +21 <LBB0_165>
     583:	r0 = r5
     584:	r0 += 3
     585:	if r0 > r2 goto +586 <LBB0_322>
     586:	r0 = *(u8 *)(r5 + 0)
     587:	r9 = 2
     588:	if r9 > r0 goto +11 <LBB0_163>
     589:	if r0 == 30 goto +1 <LBB0_162>
     590:	goto +11 <LBB0_164>

0000000000001278 LBB0_162:
;         pos += opt->len;
     591:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
     592:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
     593:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
     594:	r9 >>= 4
     595:	r0 = 1
     596:	r0 <<= r9
     597:	r0 |= r8
     598:	r8 = r0
     599:	goto +4 <LBB0_165>

00000000000012c0 LBB0_163:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     600:	r5 += 1
     601:	goto +2 <LBB0_165>

00000000000012d0 LBB0_164:
     602:	r0 = *(u8 *)(r5 + 1)
     603:	r5 += r0

00000000000012e0 LBB0_165:
;         int curr_idx = pos - start;
     604:	r0 = r5
     605:	r0 -= r4
     606:	r0 <<= 32
     607:	r9 = r0
     608:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
     609:	if r9 s>= r3 goto +562 <LBB0_322>
;         int curr_idx = pos - start;
     610:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     611:	if r0 != 20 goto +21 <LBB0_173>
     612:	r0 = r5
     613:	r0 += 3
     614:	if r0 > r2 goto +557 <LBB0_322>
     615:	r0 = *(u8 *)(r5 + 0)
     616:	r9 = 2
     617:	if r9 > r0 goto +11 <LBB0_171>
     618:	if r0 == 30 goto +1 <LBB0_170>
     619:	goto +11 <LBB0_172>

0000000000001360 LBB0_170:
;         pos += opt->len;
     620:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
     621:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
     622:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
     623:	r9 >>= 4
     624:	r0 = 1
     625:	r0 <<= r9
     626:	r0 |= r8
     627:	r8 = r0
     628:	goto +4 <LBB0_173>

00000000000013a8 LBB0_171:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     629:	r5 += 1
     630:	goto +2 <LBB0_173>

00000000000013b8 LBB0_172:
     631:	r0 = *(u8 *)(r5 + 1)
     632:	r5 += r0

00000000000013c8 LBB0_173:
;         int curr_idx = pos - start;
     633:	r0 = r5
     634:	r0 -= r4
     635:	r0 <<= 32
     636:	r9 = r0
     637:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
     638:	if r9 s>= r3 goto +533 <LBB0_322>
;         int curr_idx = pos - start;
     639:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     640:	if r0 != 21 goto +21 <LBB0_181>
     641:	r0 = r5
     642:	r0 += 3
     643:	if r0 > r2 goto +528 <LBB0_322>
     644:	r0 = *(u8 *)(r5 + 0)
     645:	r9 = 2
     646:	if r9 > r0 goto +11 <LBB0_179>
     647:	if r0 == 30 goto +1 <LBB0_178>
     648:	goto +11 <LBB0_180>

0000000000001448 LBB0_178:
;         pos += opt->len;
     649:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
     650:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
     651:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
     652:	r9 >>= 4
     653:	r0 = 1
     654:	r0 <<= r9
     655:	r0 |= r8
     656:	r8 = r0
     657:	goto +4 <LBB0_181>

0000000000001490 LBB0_179:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     658:	r5 += 1
     659:	goto +2 <LBB0_181>

00000000000014a0 LBB0_180:
     660:	r0 = *(u8 *)(r5 + 1)
     661:	r5 += r0

00000000000014b0 LBB0_181:
;         int curr_idx = pos - start;
     662:	r0 = r5
     663:	r0 -= r4
     664:	r0 <<= 32
     665:	r9 = r0
     666:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
     667:	if r9 s>= r3 goto +504 <LBB0_322>
;         int curr_idx = pos - start;
     668:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     669:	if r0 != 22 goto +21 <LBB0_189>
     670:	r0 = r5
     671:	r0 += 3
     672:	if r0 > r2 goto +499 <LBB0_322>
     673:	r0 = *(u8 *)(r5 + 0)
     674:	r9 = 2
     675:	if r9 > r0 goto +11 <LBB0_187>
     676:	if r0 == 30 goto +1 <LBB0_186>
     677:	goto +11 <LBB0_188>

0000000000001530 LBB0_186:
;         pos += opt->len;
     678:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
     679:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
     680:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
     681:	r9 >>= 4
     682:	r0 = 1
     683:	r0 <<= r9
     684:	r0 |= r8
     685:	r8 = r0
     686:	goto +4 <LBB0_189>

0000000000001578 LBB0_187:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     687:	r5 += 1
     688:	goto +2 <LBB0_189>

0000000000001588 LBB0_188:
     689:	r0 = *(u8 *)(r5 + 1)
     690:	r5 += r0

0000000000001598 LBB0_189:
;         int curr_idx = pos - start;
     691:	r0 = r5
     692:	r0 -= r4
     693:	r0 <<= 32
     694:	r9 = r0
     695:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
     696:	if r9 s>= r3 goto +475 <LBB0_322>
;         int curr_idx = pos - start;
     697:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     698:	if r0 != 23 goto +21 <LBB0_197>
     699:	r0 = r5
     700:	r0 += 3
     701:	if r0 > r2 goto +470 <LBB0_322>
     702:	r0 = *(u8 *)(r5 + 0)
     703:	r9 = 2
     704:	if r9 > r0 goto +11 <LBB0_195>
     705:	if r0 == 30 goto +1 <LBB0_194>
     706:	goto +11 <LBB0_196>

0000000000001618 LBB0_194:
;         pos += opt->len;
     707:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
     708:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
     709:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
     710:	r9 >>= 4
     711:	r0 = 1
     712:	r0 <<= r9
     713:	r0 |= r8
     714:	r8 = r0
     715:	goto +4 <LBB0_197>

0000000000001660 LBB0_195:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     716:	r5 += 1
     717:	goto +2 <LBB0_197>

0000000000001670 LBB0_196:
     718:	r0 = *(u8 *)(r5 + 1)
     719:	r5 += r0

0000000000001680 LBB0_197:
;         int curr_idx = pos - start;
     720:	r0 = r5
     721:	r0 -= r4
     722:	r0 <<= 32
     723:	r9 = r0
     724:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
     725:	if r9 s>= r3 goto +446 <LBB0_322>
;         int curr_idx = pos - start;
     726:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     727:	if r0 != 24 goto +21 <LBB0_205>
     728:	r0 = r5
     729:	r0 += 3
     730:	if r0 > r2 goto +441 <LBB0_322>
     731:	r0 = *(u8 *)(r5 + 0)
     732:	r9 = 2
     733:	if r9 > r0 goto +11 <LBB0_203>
     734:	if r0 == 30 goto +1 <LBB0_202>
     735:	goto +11 <LBB0_204>

0000000000001700 LBB0_202:
;         pos += opt->len;
     736:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
     737:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
     738:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
     739:	r9 >>= 4
     740:	r0 = 1
     741:	r0 <<= r9
     742:	r0 |= r8
     743:	r8 = r0
     744:	goto +4 <LBB0_205>

0000000000001748 LBB0_203:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     745:	r5 += 1
     746:	goto +2 <LBB0_205>

0000000000001758 LBB0_204:
     747:	r0 = *(u8 *)(r5 + 1)
     748:	r5 += r0

0000000000001768 LBB0_205:
;         int curr_idx = pos - start;
     749:	r0 = r5
     750:	r0 -= r4
     751:	r0 <<= 32
     752:	r9 = r0
     753:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
     754:	if r9 s>= r3 goto +417 <LBB0_322>
;         int curr_idx = pos - start;
     755:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     756:	if r0 != 25 goto +21 <LBB0_213>
     757:	r0 = r5
     758:	r0 += 3
     759:	if r0 > r2 goto +412 <LBB0_322>
     760:	r0 = *(u8 *)(r5 + 0)
     761:	r9 = 2
     762:	if r9 > r0 goto +11 <LBB0_211>
     763:	if r0 == 30 goto +1 <LBB0_210>
     764:	goto +11 <LBB0_212>

00000000000017e8 LBB0_210:
;         pos += opt->len;
     765:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
     766:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
     767:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
     768:	r9 >>= 4
     769:	r0 = 1
     770:	r0 <<= r9
     771:	r0 |= r8
     772:	r8 = r0
     773:	goto +4 <LBB0_213>

0000000000001830 LBB0_211:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     774:	r5 += 1
     775:	goto +2 <LBB0_213>

0000000000001840 LBB0_212:
     776:	r0 = *(u8 *)(r5 + 1)
     777:	r5 += r0

0000000000001850 LBB0_213:
;         int curr_idx = pos - start;
     778:	r0 = r5
     779:	r0 -= r4
     780:	r0 <<= 32
     781:	r9 = r0
     782:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
     783:	if r9 s>= r3 goto +388 <LBB0_322>
;         int curr_idx = pos - start;
     784:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     785:	if r0 != 26 goto +21 <LBB0_221>
     786:	r0 = r5
     787:	r0 += 3
     788:	if r0 > r2 goto +383 <LBB0_322>
     789:	r0 = *(u8 *)(r5 + 0)
     790:	r9 = 2
     791:	if r9 > r0 goto +11 <LBB0_219>
     792:	if r0 == 30 goto +1 <LBB0_218>
     793:	goto +11 <LBB0_220>

00000000000018d0 LBB0_218:
;         pos += opt->len;
     794:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
     795:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
     796:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
     797:	r9 >>= 4
     798:	r0 = 1
     799:	r0 <<= r9
     800:	r0 |= r8
     801:	r8 = r0
     802:	goto +4 <LBB0_221>

0000000000001918 LBB0_219:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     803:	r5 += 1
     804:	goto +2 <LBB0_221>

0000000000001928 LBB0_220:
     805:	r0 = *(u8 *)(r5 + 1)
     806:	r5 += r0

0000000000001938 LBB0_221:
;         int curr_idx = pos - start;
     807:	r0 = r5
     808:	r0 -= r4
     809:	r0 <<= 32
     810:	r9 = r0
     811:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
     812:	if r9 s>= r3 goto +359 <LBB0_322>
;         int curr_idx = pos - start;
     813:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     814:	if r0 != 27 goto +21 <LBB0_229>
     815:	r0 = r5
     816:	r0 += 3
     817:	if r0 > r2 goto +354 <LBB0_322>
     818:	r0 = *(u8 *)(r5 + 0)
     819:	r9 = 2
     820:	if r9 > r0 goto +11 <LBB0_227>
     821:	if r0 == 30 goto +1 <LBB0_226>
     822:	goto +11 <LBB0_228>

00000000000019b8 LBB0_226:
;         pos += opt->len;
     823:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
     824:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
     825:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
     826:	r9 >>= 4
     827:	r0 = 1
     828:	r0 <<= r9
     829:	r0 |= r8
     830:	r8 = r0
     831:	goto +4 <LBB0_229>

0000000000001a00 LBB0_227:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     832:	r5 += 1
     833:	goto +2 <LBB0_229>

0000000000001a10 LBB0_228:
     834:	r0 = *(u8 *)(r5 + 1)
     835:	r5 += r0

0000000000001a20 LBB0_229:
;         int curr_idx = pos - start;
     836:	r0 = r5
     837:	r0 -= r4
     838:	r0 <<= 32
     839:	r9 = r0
     840:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
     841:	if r9 s>= r3 goto +330 <LBB0_322>
;         int curr_idx = pos - start;
     842:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     843:	if r0 != 28 goto +21 <LBB0_237>
     844:	r0 = r5
     845:	r0 += 3
     846:	if r0 > r2 goto +325 <LBB0_322>
     847:	r0 = *(u8 *)(r5 + 0)
     848:	r9 = 2
     849:	if r9 > r0 goto +11 <LBB0_235>
     850:	if r0 == 30 goto +1 <LBB0_234>
     851:	goto +11 <LBB0_236>

0000000000001aa0 LBB0_234:
;         pos += opt->len;
     852:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
     853:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
     854:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
     855:	r9 >>= 4
     856:	r0 = 1
     857:	r0 <<= r9
     858:	r0 |= r8
     859:	r8 = r0
     860:	goto +4 <LBB0_237>

0000000000001ae8 LBB0_235:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     861:	r5 += 1
     862:	goto +2 <LBB0_237>

0000000000001af8 LBB0_236:
     863:	r0 = *(u8 *)(r5 + 1)
     864:	r5 += r0

0000000000001b08 LBB0_237:
;         int curr_idx = pos - start;
     865:	r0 = r5
     866:	r0 -= r4
     867:	r0 <<= 32
     868:	r9 = r0
     869:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
     870:	if r9 s>= r3 goto +301 <LBB0_322>
;         int curr_idx = pos - start;
     871:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     872:	if r0 != 29 goto +21 <LBB0_245>
     873:	r0 = r5
     874:	r0 += 3
     875:	if r0 > r2 goto +296 <LBB0_322>
     876:	r0 = *(u8 *)(r5 + 0)
     877:	r9 = 2
     878:	if r9 > r0 goto +11 <LBB0_243>
     879:	if r0 == 30 goto +1 <LBB0_242>
     880:	goto +11 <LBB0_244>

0000000000001b88 LBB0_242:
;         pos += opt->len;
     881:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
     882:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
     883:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
     884:	r9 >>= 4
     885:	r0 = 1
     886:	r0 <<= r9
     887:	r0 |= r8
     888:	r8 = r0
     889:	goto +4 <LBB0_245>

0000000000001bd0 LBB0_243:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     890:	r5 += 1
     891:	goto +2 <LBB0_245>

0000000000001be0 LBB0_244:
     892:	r0 = *(u8 *)(r5 + 1)
     893:	r5 += r0

0000000000001bf0 LBB0_245:
;         int curr_idx = pos - start;
     894:	r0 = r5
     895:	r0 -= r4
     896:	r0 <<= 32
     897:	r9 = r0
     898:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
     899:	if r9 s>= r3 goto +272 <LBB0_322>
;         int curr_idx = pos - start;
     900:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     901:	if r0 != 30 goto +21 <LBB0_253>
     902:	r0 = r5
     903:	r0 += 3
     904:	if r0 > r2 goto +267 <LBB0_322>
     905:	r0 = *(u8 *)(r5 + 0)
     906:	r9 = 2
     907:	if r9 > r0 goto +11 <LBB0_251>
     908:	if r0 == 30 goto +1 <LBB0_250>
     909:	goto +11 <LBB0_252>

0000000000001c70 LBB0_250:
;         pos += opt->len;
     910:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
     911:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
     912:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
     913:	r9 >>= 4
     914:	r0 = 1
     915:	r0 <<= r9
     916:	r0 |= r8
     917:	r8 = r0
     918:	goto +4 <LBB0_253>

0000000000001cb8 LBB0_251:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     919:	r5 += 1
     920:	goto +2 <LBB0_253>

0000000000001cc8 LBB0_252:
     921:	r0 = *(u8 *)(r5 + 1)
     922:	r5 += r0

0000000000001cd8 LBB0_253:
;         int curr_idx = pos - start;
     923:	r0 = r5
     924:	r0 -= r4
     925:	r0 <<= 32
     926:	r9 = r0
     927:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
     928:	if r9 s>= r3 goto +243 <LBB0_322>
;         int curr_idx = pos - start;
     929:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     930:	if r0 != 31 goto +21 <LBB0_261>
     931:	r0 = r5
     932:	r0 += 3
     933:	if r0 > r2 goto +238 <LBB0_322>
     934:	r0 = *(u8 *)(r5 + 0)
     935:	r9 = 2
     936:	if r9 > r0 goto +11 <LBB0_259>
     937:	if r0 == 30 goto +1 <LBB0_258>
     938:	goto +11 <LBB0_260>

0000000000001d58 LBB0_258:
;         pos += opt->len;
     939:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
     940:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
     941:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
     942:	r9 >>= 4
     943:	r0 = 1
     944:	r0 <<= r9
     945:	r0 |= r8
     946:	r8 = r0
     947:	goto +4 <LBB0_261>

0000000000001da0 LBB0_259:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     948:	r5 += 1
     949:	goto +2 <LBB0_261>

0000000000001db0 LBB0_260:
     950:	r0 = *(u8 *)(r5 + 1)
     951:	r5 += r0

0000000000001dc0 LBB0_261:
;         int curr_idx = pos - start;
     952:	r0 = r5
     953:	r0 -= r4
     954:	r0 <<= 32
     955:	r9 = r0
     956:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
     957:	if r9 s>= r3 goto +214 <LBB0_322>
;         int curr_idx = pos - start;
     958:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     959:	if r0 != 32 goto +21 <LBB0_269>
     960:	r0 = r5
     961:	r0 += 3
     962:	if r0 > r2 goto +209 <LBB0_322>
     963:	r0 = *(u8 *)(r5 + 0)
     964:	r9 = 2
     965:	if r9 > r0 goto +11 <LBB0_267>
     966:	if r0 == 30 goto +1 <LBB0_266>
     967:	goto +11 <LBB0_268>

0000000000001e40 LBB0_266:
;         pos += opt->len;
     968:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
     969:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
     970:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
     971:	r9 >>= 4
     972:	r0 = 1
     973:	r0 <<= r9
     974:	r0 |= r8
     975:	r8 = r0
     976:	goto +4 <LBB0_269>

0000000000001e88 LBB0_267:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     977:	r5 += 1
     978:	goto +2 <LBB0_269>

0000000000001e98 LBB0_268:
     979:	r0 = *(u8 *)(r5 + 1)
     980:	r5 += r0

0000000000001ea8 LBB0_269:
;         int curr_idx = pos - start;
     981:	r0 = r5
     982:	r0 -= r4
     983:	r0 <<= 32
     984:	r9 = r0
     985:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
     986:	if r9 s>= r3 goto +185 <LBB0_322>
;         int curr_idx = pos - start;
     987:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
     988:	if r0 != 33 goto +21 <LBB0_277>
     989:	r0 = r5
     990:	r0 += 3
     991:	if r0 > r2 goto +180 <LBB0_322>
     992:	r0 = *(u8 *)(r5 + 0)
     993:	r9 = 2
     994:	if r9 > r0 goto +11 <LBB0_275>
     995:	if r0 == 30 goto +1 <LBB0_274>
     996:	goto +11 <LBB0_276>

0000000000001f28 LBB0_274:
;         pos += opt->len;
     997:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
     998:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
     999:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
    1000:	r9 >>= 4
    1001:	r0 = 1
    1002:	r0 <<= r9
    1003:	r0 |= r8
    1004:	r8 = r0
    1005:	goto +4 <LBB0_277>

0000000000001f70 LBB0_275:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
    1006:	r5 += 1
    1007:	goto +2 <LBB0_277>

0000000000001f80 LBB0_276:
    1008:	r0 = *(u8 *)(r5 + 1)
    1009:	r5 += r0

0000000000001f90 LBB0_277:
;         int curr_idx = pos - start;
    1010:	r0 = r5
    1011:	r0 -= r4
    1012:	r0 <<= 32
    1013:	r9 = r0
    1014:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
    1015:	if r9 s>= r3 goto +156 <LBB0_322>
;         int curr_idx = pos - start;
    1016:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
    1017:	if r0 != 34 goto +21 <LBB0_285>
    1018:	r0 = r5
    1019:	r0 += 3
    1020:	if r0 > r2 goto +151 <LBB0_322>
    1021:	r0 = *(u8 *)(r5 + 0)
    1022:	r9 = 2
    1023:	if r9 > r0 goto +11 <LBB0_283>
    1024:	if r0 == 30 goto +1 <LBB0_282>
    1025:	goto +11 <LBB0_284>

0000000000002010 LBB0_282:
;         pos += opt->len;
    1026:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
    1027:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
    1028:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
    1029:	r9 >>= 4
    1030:	r0 = 1
    1031:	r0 <<= r9
    1032:	r0 |= r8
    1033:	r8 = r0
    1034:	goto +4 <LBB0_285>

0000000000002058 LBB0_283:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
    1035:	r5 += 1
    1036:	goto +2 <LBB0_285>

0000000000002068 LBB0_284:
    1037:	r0 = *(u8 *)(r5 + 1)
    1038:	r5 += r0

0000000000002078 LBB0_285:
;         int curr_idx = pos - start;
    1039:	r0 = r5
    1040:	r0 -= r4
    1041:	r0 <<= 32
    1042:	r9 = r0
    1043:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
    1044:	if r9 s>= r3 goto +127 <LBB0_322>
;         int curr_idx = pos - start;
    1045:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
    1046:	if r0 != 35 goto +21 <LBB0_293>
    1047:	r0 = r5
    1048:	r0 += 3
    1049:	if r0 > r2 goto +122 <LBB0_322>
    1050:	r0 = *(u8 *)(r5 + 0)
    1051:	r9 = 2
    1052:	if r9 > r0 goto +11 <LBB0_291>
    1053:	if r0 == 30 goto +1 <LBB0_290>
    1054:	goto +11 <LBB0_292>

00000000000020f8 LBB0_290:
;         pos += opt->len;
    1055:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
    1056:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
    1057:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
    1058:	r9 >>= 4
    1059:	r0 = 1
    1060:	r0 <<= r9
    1061:	r0 |= r8
    1062:	r8 = r0
    1063:	goto +4 <LBB0_293>

0000000000002140 LBB0_291:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
    1064:	r5 += 1
    1065:	goto +2 <LBB0_293>

0000000000002150 LBB0_292:
    1066:	r0 = *(u8 *)(r5 + 1)
    1067:	r5 += r0

0000000000002160 LBB0_293:
;         int curr_idx = pos - start;
    1068:	r0 = r5
    1069:	r0 -= r4
    1070:	r0 <<= 32
    1071:	r9 = r0
    1072:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
    1073:	if r9 s>= r3 goto +98 <LBB0_322>
;         int curr_idx = pos - start;
    1074:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
    1075:	if r0 != 36 goto +21 <LBB0_301>
    1076:	r0 = r5
    1077:	r0 += 3
    1078:	if r0 > r2 goto +93 <LBB0_322>
    1079:	r0 = *(u8 *)(r5 + 0)
    1080:	r9 = 2
    1081:	if r9 > r0 goto +11 <LBB0_299>
    1082:	if r0 == 30 goto +1 <LBB0_298>
    1083:	goto +11 <LBB0_300>

00000000000021e0 LBB0_298:
;         pos += opt->len;
    1084:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
    1085:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
    1086:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
    1087:	r9 >>= 4
    1088:	r0 = 1
    1089:	r0 <<= r9
    1090:	r0 |= r8
    1091:	r8 = r0
    1092:	goto +4 <LBB0_301>

0000000000002228 LBB0_299:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
    1093:	r5 += 1
    1094:	goto +2 <LBB0_301>

0000000000002238 LBB0_300:
    1095:	r0 = *(u8 *)(r5 + 1)
    1096:	r5 += r0

0000000000002248 LBB0_301:
;         int curr_idx = pos - start;
    1097:	r0 = r5
    1098:	r0 -= r4
    1099:	r0 <<= 32
    1100:	r9 = r0
    1101:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
    1102:	if r9 s>= r3 goto +69 <LBB0_322>
;         int curr_idx = pos - start;
    1103:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
    1104:	if r0 != 37 goto +21 <LBB0_309>
    1105:	r0 = r5
    1106:	r0 += 3
    1107:	if r0 > r2 goto +64 <LBB0_322>
    1108:	r0 = *(u8 *)(r5 + 0)
    1109:	r9 = 2
    1110:	if r9 > r0 goto +11 <LBB0_307>
    1111:	if r0 == 30 goto +1 <LBB0_306>
    1112:	goto +11 <LBB0_308>

00000000000022c8 LBB0_306:
;         pos += opt->len;
    1113:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
    1114:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
    1115:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
    1116:	r9 >>= 4
    1117:	r0 = 1
    1118:	r0 <<= r9
    1119:	r0 |= r8
    1120:	r8 = r0
    1121:	goto +4 <LBB0_309>

0000000000002310 LBB0_307:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
    1122:	r5 += 1
    1123:	goto +2 <LBB0_309>

0000000000002320 LBB0_308:
    1124:	r0 = *(u8 *)(r5 + 1)
    1125:	r5 += r0

0000000000002330 LBB0_309:
;         int curr_idx = pos - start;
    1126:	r0 = r5
    1127:	r0 -= r4
    1128:	r0 <<= 32
    1129:	r9 = r0
    1130:	r9 s>>= 32
;         if (curr_idx >= tcp_opt_len) return;
    1131:	if r9 s>= r3 goto +40 <LBB0_322>
;         int curr_idx = pos - start;
    1132:	r0 >>= 32
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
    1133:	if r0 != 38 goto +21 <LBB0_317>
    1134:	r0 = r5
    1135:	r0 += 3
    1136:	if r0 > r2 goto +35 <LBB0_322>
    1137:	r0 = *(u8 *)(r5 + 0)
    1138:	r9 = 2
    1139:	if r9 > r0 goto +11 <LBB0_315>
    1140:	if r0 == 30 goto +1 <LBB0_314>
    1141:	goto +11 <LBB0_316>

00000000000023b0 LBB0_314:
;         pos += opt->len;
    1142:	r0 = *(u8 *)(r5 + 1)
;         *opt_flags |= (1 << opt->sub);
    1143:	r9 = *(u8 *)(r5 + 2)
;         pos += opt->len;
    1144:	r5 += r0
;         *opt_flags |= (1 << opt->sub);
    1145:	r9 >>= 4
    1146:	r0 = 1
    1147:	r0 <<= r9
    1148:	r0 |= r8
    1149:	r8 = r0
    1150:	goto +4 <LBB0_317>

00000000000023f8 LBB0_315:
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
    1151:	r5 += 1
    1152:	goto +2 <LBB0_317>

0000000000002408 LBB0_316:
    1153:	r0 = *(u8 *)(r5 + 1)
    1154:	r5 += r0

0000000000002418 LBB0_317:
    1155:	r0 = r5
    1156:	r0 += 3
;         if (curr_idx >= tcp_opt_len) return;
    1157:	if r0 > r2 goto +14 <LBB0_322>
    1158:	r2 = r5
    1159:	r2 -= r4
    1160:	r2 <<= 32
    1161:	r2 s>>= 32
    1162:	if r2 != 39 goto +9 <LBB0_322>
    1163:	if r2 s>= r3 goto +8 <LBB0_322>
;         if (curr_idx == index) SCAN_MPTCP_OPT(pos, data_end);
    1164:	r2 = *(u8 *)(r5 + 0)
    1165:	if r2 != 30 goto +6 <LBB0_322>
;         *opt_flags |= (1 << opt->sub);
    1166:	r2 = *(u8 *)(r5 + 2)
    1167:	r2 >>= 4
    1168:	r3 = 1
    1169:	r3 <<= r2
    1170:	r3 |= r8
    1171:	r8 = r3

00000000000024a0 LBB0_322:
;     if (!tcph->syn && (mptcp_flags & MPTCP_SUB_CAPABLE_FLAG)) {
    1172:	r2 = r8
    1173:	r2 &= 1
    1174:	if r2 == 0 goto +10 <LBB0_325>
    1175:	r1 &= 512
    1176:	if r1 != 0 goto +8 <LBB0_325>
;         res = bpf_tail_call(skb, &tc_egress_tailcall, 0);  // 0 is mpcabable sub
    1177:	r1 = r6
    1178:	r2 = 0 ll
    1180:	r3 = 0
    1181:	call 12
    1182:	r0 <<= 32
    1183:	r0 >>= 32
;         if (res != 0) {
    1184:	if r0 != 0 goto +47 <LBB0_333>

0000000000002508 LBB0_325:
;     if ((mptcp_flags & MPTCP_SUB_JOIN_FLAG) && tcph->syn && !tcph->ack) {
    1185:	r1 = r8
    1186:	r1 &= 2
    1187:	if r1 == 0 goto +11 <LBB0_328>
    1188:	r1 = *(u16 *)(r7 + 46)
    1189:	r1 &= 4608
    1190:	if r1 != 512 goto +8 <LBB0_328>
;         res = bpf_tail_call(skb, &tc_egress_tailcall, 1);  // 1 is mpcabable join
    1191:	r1 = r6
    1192:	r2 = 0 ll
    1194:	r3 = 1
    1195:	call 12
    1196:	r0 <<= 32
    1197:	r0 >>= 32
;         if (res != 0) {
    1198:	if r0 != 0 goto +33 <LBB0_333>

0000000000002578 LBB0_328:
;     if (mptcp_flags & MPTCP_SUB_DSS_FLAG) {
    1199:	r8 &= 4
    1200:	if r8 == 0 goto +14 <LBB0_330>
;     flow_key.local_addr = iph->saddr;
    1201:	r1 = *(u32 *)(r7 + 26)
    1202:	*(u32 *)(r10 - 24) = r1
;     flow_key.peer_addr = iph->daddr;
    1203:	r1 = *(u32 *)(r7 + 30)
    1204:	*(u32 *)(r10 - 20) = r1
;     flow_key.local_port = tcph->source;
    1205:	r1 = *(u16 *)(r7 + 34)
    1206:	*(u16 *)(r10 - 16) = r1
;     flow_key.peer_port = tcph->dest;
    1207:	r1 = *(u16 *)(r7 + 36)
    1208:	*(u16 *)(r10 - 14) = r1
    1209:	r2 = r10
;     flow_key.local_addr = iph->saddr;
    1210:	r2 += -24
;     sub = bpf_map_lookup_elem(&subflows, &flow_key);
    1211:	r1 = 0 ll
    1213:	call 1
;     if (sub == NULL) return -NOT_TARGET;
    1214:	if r0 != 0 goto +34 <LBB0_334>

00000000000025f8 LBB0_330:
    1215:	r1 = 0
;     bpfprintk("main not target! \n");
    1216:	*(u8 *)(r10 - 6) = r1
    1217:	r1 = 2592
    1218:	*(u16 *)(r10 - 8) = r1
    1219:	r1 = 2410663195525084192 ll
    1221:	*(u64 *)(r10 - 16) = r1
    1222:	r1 = 8390045716384932205 ll
    1224:	*(u64 *)(r10 - 24) = r1
    1225:	r1 = r10
; not_target:
    1226:	r1 += -24
;     bpfprintk("main not target! \n");
    1227:	r2 = 19

0000000000002660 LBB0_331:
    1228:	call 6

0000000000002668 LBB0_332:
; }
    1229:	r0 = 4294967295 ll
    1231:	exit

0000000000002680 LBB0_333:
    1232:	r1 = 10
;     bpfprintk("main failed! res: %d\n", res);
    1233:	*(u16 *)(r10 - 4) = r1
    1234:	r1 = 1680154682
    1235:	*(u32 *)(r10 - 8) = r1
    1236:	r1 = 8315177769334236524 ll
    1238:	*(u64 *)(r10 - 16) = r1
    1239:	r1 = 7593462736200753517 ll
    1241:	*(u64 *)(r10 - 24) = r1
    1242:	r1 = r10
    1243:	r1 += -24
    1244:	r2 = 22
    1245:	r3 = 4294966290 ll
    1247:	call 6
    1248:	goto -20 <LBB0_332>

0000000000002708 LBB0_334:
;     return tot_len - 20 - ((tcph->doff) << 2);
    1249:	r1 = *(u16 *)(r7 + 46)
;     int tot_len= bpf_htons(iph->tot_len);
    1250:	r2 = *(u16 *)(r7 + 16)
    1251:	r3 = 1
;     lock_xadd(&sub->sended_pkts, 1);
    1252:	lock *(u32 *)(r0 + 8) += r3
    1253:	r2 = be16 r2
;     return tot_len - 20 - ((tcph->doff) << 2);
    1254:	r1 >>= 2
    1255:	r1 &= 60
    1256:	r2 -= r1
    1257:	r2 += -20
;     lock_xadd(&sub->sended_data, data_len);
    1258:	lock *(u64 *)(r0 + 16) += r2
    1259:	r1 = 2850077810058595 ll
;     bpfprintk("main success! \n");
    1261:	*(u64 *)(r10 - 16) = r1
    1262:	r1 = 7166760965158560109 ll
    1264:	*(u64 *)(r10 - 24) = r1
    1265:	r1 = r10
    1266:	r1 += -24
    1267:	r2 = 16
    1268:	goto -41 <LBB0_331>
