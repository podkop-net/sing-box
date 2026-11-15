package urltestgroup

// quicLossPrice is the price of the loss of a member over QUIC (podkop-engine), measured on the
// stand of report 02 (grid g16 of lab/hy2, 2026-11-15): hysteria2 of sing-box 1.14.4, its pages at
// RTTs of 20 to 150 ms and losses of 0.5 to 10 % on both ways, the server sending with BBR, as it
// does when the client declares no rate. It is fitted, by least squares, to the slowdown itself (a
// page at the loss p over a page without loss at the same RTT), so perRTT is 1, over the 12 cells
// of 0.5 to 2 %: where a member is chosen over another. The slowdown is concave in the loss (at 50
// ms and more, 0.5 % costs about what 1 % does), and a fit over all 24 cells, pulled by those of 5
// and 10 %, priced 1 % at x1.24 at 100 ms where the grid measured x1.45. Measured, then priced, at
// 1 %: x1.05 and x1.03 at 20 ms, x1.27 and x1.34 at 50 ms, x1.45 and x1.44 at 100 ms, x1.62 and
// x1.48 at 150 ms (residuals of 0.20 rms over these cells); 5 and 10 % are priced above what they
// cost (x5.4 for x3.3 at 100 ms and 10 %), so a member that loses that much loses its place a
// little sooner. A lost packet costs its stream a round of recovery and no new connection a
// handshake timer: over TCP the cost falls with the RTT (tcpLossPrice: x2.85 at 20 ms, x1.57 at
// 100 ms), over QUIC it grows with it. No RTT below 20 ms was measured: a shorter one is priced as
// 20 ms (minRTT), where the fitted form would price any loss at nothing below 19 ms. With Brutal
// (a rate declared) a loss costs less (x1.03 to x1.14 at 1 %), so this price weighs such a member
// more than its loss costs. TUIC was not measured and is priced as hysteria2.
var quicLossPrice = lossPrice{perRTT: 1, perLoss: -10.28, perLossRTT: 0.5438, minRTT: 20}
