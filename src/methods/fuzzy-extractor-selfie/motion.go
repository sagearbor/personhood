package fuzzyextractorselfie

// Motion and light consistency checks for the native selfie ceremony
// (native.go). The phone records, on one clock, what its camera saw (per
// frame: where the face is, how far the background shifted since the last
// frame, the mean colour of face and background) and what its gyroscope
// and accelerometer felt. This file decides whether the two stories agree.
//
// Three checks, all on numbers the issuer recomputes from the raw trace:
//
//  1. Rotation (required). While the person sweeps the phone, a rotation of
//     the camera by w rad/s moves everything in the image by about f*w
//     pixels/s, whatever its depth. The image shift predicted from the gyro
//     must match the measured shift (Pearson r and gain). A video that was
//     not filmed by this phone's camera during this motion does not match.
//  2. Parallax (one of 2 or 3). A hand sweep also translates the phone, and
//     translation moves near things more than far things. On a real scene
//     the face (about 0.3 m away) and the background (metres away) have
//     different gains against the gyro; on a flat picture or a screen both
//     sit at one depth and have the same gain.
//  3. Flash (one of 2 or 3). The screen shows a random colour sequence
//     chosen by the issuer. Light from the screen reaches a face 0.3 m away
//     far more than the room behind it, so the face's colour must follow
//     the sequence (with a short display-to-camera delay) and the
//     background's much less. A replayed video does not know the sequence,
//     and a flat screen in front of the camera reflects it evenly.
//
// The thresholds below are first guesses tuned on synthetic traces
// (motion_test.go reports false-reject and false-accept rates on them).
// They have NOT been calibrated on real phones yet; the Pixel 10 test is
// the first real data. A failure here never locks anyone out: the client
// falls back to the web-strength ceremony (docs/selfie-anchor.md).

import (
	"math"
	"sort"
)

// Frame columns in NativeTrace.Frames.
const (
	frT       = iota // ms since ceremony start, shared clock with IMU
	frFaceX          // face centre, px
	frFaceY          //
	frFaceW          // face width, px
	frBgDX           // background shift since the previous frame, px
	frBgDY           //
	frBgQ            // background texture quality 0..1 (how trustworthy the shift is)
	frFaceR          // face mean colour, 0..255
	frFaceG          //
	frFaceB          //
	frBgR            // background mean colour
	frBgG            //
	frBgB            //
	frameCols        // number of columns
)

// IMU columns in NativeTrace.IMU (device axes, Android convention:
// x right, y up, z out of the screen; gyro rad/s, accel m/s^2).
const (
	imuT = iota
	imuGX
	imuGY
	imuGZ
	imuAX
	imuAY
	imuAZ
	imuCols
)

// Trace size limits, so a request cannot make the issuer do unbounded work.
const (
	maxTraceFrames  = 4000
	maxTraceSamples = 40000
)

// NativeDevice describes the capture.
type NativeDevice struct {
	Model string `json:"model,omitempty"`
	SDK   int    `json:"sdk,omitempty"`
	Gyro  bool   `json:"gyro"`
	// Clock says how camera timestamps were put on the sensor clock:
	// "realtime" (Camera2 SENSOR_INFO_TIMESTAMP_SOURCE_REALTIME) or
	// "converted" (monotonic timestamps shifted by the boot-time offset).
	Clock string `json:"clock,omitempty"`
	// FocalPx is the camera focal length in pixels of the analysed image.
	FocalPx float64 `json:"focal_px"`
	Width   int     `json:"width"`
	Height  int     `json:"height"`
}

// NativeTrace is the raw evidence of the native ceremony.
type NativeTrace struct {
	Device NativeDevice `json:"device"`
	Frames [][]float64  `json:"frames"`
	IMU    [][]float64  `json:"imu"`
	// Sweep is [start, end] ms of the "swing the phone" phase.
	Sweep [2]float64 `json:"sweep"`
	// Flash is the display time (ms) of each colour segment's start, plus
	// the end of the last one: len = number of colours + 1.
	Flash []float64 `json:"flash"`
}

// NativeThresholds tunes the checks. Zero fields take the defaults.
type NativeThresholds struct {
	MinSweepPairs int     // frame pairs in the sweep window (default 20)
	MinSweepRate  float64 // RMS gyro rate during the sweep, rad/s (default 0.15)
	MinRotationR  float64 // default 0.9
	MinGain       float64 // background gain against the gyro, default 0.6
	MaxGain       float64 // default 1.6
	MinFaceGain   float64 // face gain when the background has no texture, default 0.3
	MaxFaceGain   float64 // default 3 (a near face moves more under translation)
	// FitSigns also tries the opposite image-axis signs. Off by default:
	// the signs follow from the axis conventions (predictedShift), and
	// letting them float doubles the chance that an unrelated video
	// correlates. Turn it on only to calibrate a phone whose mapping
	// differs.
	FitSigns        bool
	MaxLagMS        float64 // camera/IMU clock offset searched, +- ms (default 80)
	MinBgQuality    float64 // default 0.3
	MinParallax     float64 // relative face/background gain difference (default 0.12)
	MinFlashFrames  int     // default 20
	MinFlashR       float64 // default 0.6
	MinFlashAmp     float64 // face chroma change per unit colour, default 0.008
	MaxFlashBgRatio float64 // background amplitude / face amplitude, default 0.5
	MaxFlashLagMS   float64 // display-to-camera delay searched, 0..ms (default 250)
	MinIMURateHz    float64 // default 50
}

func (t NativeThresholds) withDefaults() NativeThresholds {
	def := func(v *float64, d float64) {
		if *v == 0 {
			*v = d
		}
	}
	if t.MinSweepPairs == 0 {
		t.MinSweepPairs = 20
	}
	if t.MinFlashFrames == 0 {
		t.MinFlashFrames = 20
	}
	def(&t.MinSweepRate, 0.15)
	def(&t.MinRotationR, 0.9)
	def(&t.MinGain, 0.6)
	def(&t.MaxGain, 1.6)
	def(&t.MinFaceGain, 0.3)
	def(&t.MaxFaceGain, 3)
	def(&t.MaxLagMS, 80)
	def(&t.MinBgQuality, 0.3)
	def(&t.MinParallax, 0.12)
	def(&t.MinFlashR, 0.6)
	def(&t.MinFlashAmp, 0.008)
	def(&t.MaxFlashBgRatio, 0.5)
	def(&t.MaxFlashLagMS, 250)
	def(&t.MinIMURateHz, 50)
	return t
}

// Flash colours, as indexes.
const (
	FlashRed = iota
	FlashGreen
	FlashBlue
)

// FlashColourNames are the wire names of the flash colours.
var FlashColourNames = []string{"#ff0000", "#00ff00", "#0000ff"}

// CheckOutcome is one check's verdict.
type CheckOutcome string

const (
	CheckPass         CheckOutcome = "pass"
	CheckFail         CheckOutcome = "fail"
	CheckInconclusive CheckOutcome = "inconclusive" // not enough signal to judge
)

// MotionReport is the issuer's reading of a trace. It holds only scores,
// never images, and is safe to log.
type MotionReport struct {
	Rotation      CheckOutcome `json:"rotation"`
	RotationR     float64      `json:"rotation_r"`
	RotationGain  float64      `json:"rotation_gain"`
	RotationLagMS float64      `json:"rotation_lag_ms"`
	SweepRate     float64      `json:"sweep_rate"`
	SweepPairs    int          `json:"sweep_pairs"`
	// Signs are the image-axis signs that fitted best (x, y). With the
	// derivation in predictedShift both should be +1; anything else on a
	// real phone means its axis mapping differs (useful for calibration).
	Signs [2]int `json:"signs"`
	// PlainBackground: too little background texture, so the face was
	// used for the rotation check and parallax could not be measured.
	PlainBackground bool `json:"plain_background,omitempty"`

	Parallax     CheckOutcome `json:"parallax"`
	ParallaxDiff float64      `json:"parallax_diff"`
	FaceGain     float64      `json:"face_gain"`
	BgGain       float64      `json:"bg_gain"`

	Flash      CheckOutcome `json:"flash"`
	FlashR     float64      `json:"flash_r"`
	FlashAmp   float64      `json:"flash_amp"`
	FlashBgAmp float64      `json:"flash_bg_amp"`
	FlashLagMS float64      `json:"flash_lag_ms"`

	// Tremor is the share of gyro power in 6-14 Hz outside the sweep:
	// physiological hand tremor. Informational only (a robot can add it).
	Tremor float64 `json:"tremor"`

	Pass   bool   `json:"pass"`
	Reason string `json:"reason,omitempty"`
}

// AnalyzeNativeTrace runs every check. flash is the issued colour sequence.
func AnalyzeNativeTrace(tr NativeTrace, flash []int, th NativeThresholds) MotionReport {
	th = th.withDefaults()
	rep := MotionReport{Rotation: CheckInconclusive, Parallax: CheckInconclusive, Flash: CheckInconclusive}
	if reason := validateTrace(tr, th); reason != "" {
		rep.Reason = reason
		return rep
	}
	g := newGyroIntegral(tr.IMU)
	checkRotation(tr, g, th, &rep)
	if rep.Rotation == CheckPass {
		checkParallax(tr, g, th, &rep)
	}
	checkFlash(tr, flash, th, &rep)
	rep.Tremor = round3(tremorShare(tr))

	switch {
	case rep.Rotation == CheckInconclusive && rep.PlainBackground && rep.SweepRate >= th.MinSweepRate:
		rep.Reason = "native_background_plain"
	case rep.Rotation == CheckInconclusive:
		rep.Reason = "native_sweep_too_small"
	case rep.Rotation == CheckFail:
		rep.Reason = "native_motion_inconsistent"
	case rep.Parallax != CheckPass && rep.Flash != CheckPass:
		rep.Reason = "native_depth_not_seen"
	default:
		rep.Pass = true
	}
	return rep
}

func validateTrace(tr NativeTrace, th NativeThresholds) string {
	if !tr.Device.Gyro || tr.Device.FocalPx <= 0 {
		return "native_no_gyro"
	}
	if len(tr.Frames) == 0 || len(tr.Frames) > maxTraceFrames || len(tr.IMU) == 0 || len(tr.IMU) > maxTraceSamples {
		return "native_trace_invalid"
	}
	prev := math.Inf(-1)
	for _, f := range tr.Frames {
		if len(f) != frameCols || !finite(f) || f[frT] < prev {
			return "native_trace_invalid"
		}
		prev = f[frT]
	}
	prev = math.Inf(-1)
	for _, s := range tr.IMU {
		if len(s) != imuCols || !finite(s) || s[imuT] < prev {
			return "native_trace_invalid"
		}
		prev = s[imuT]
	}
	if tr.Sweep[1] <= tr.Sweep[0] {
		return "native_trace_invalid"
	}
	// IMU rate inside the sweep.
	n := 0
	for _, s := range tr.IMU {
		if s[imuT] >= tr.Sweep[0] && s[imuT] <= tr.Sweep[1] {
			n++
		}
	}
	if float64(n)/((tr.Sweep[1]-tr.Sweep[0])/1000) < th.MinIMURateHz {
		return "native_imu_too_slow"
	}
	return ""
}

func finite(v []float64) bool {
	for _, x := range v {
		if math.IsNaN(x) || math.IsInf(x, 0) {
			return false
		}
	}
	return true
}

// gyroIntegral holds the running integral of gyro x and y (rad), so the
// rotation between any two instants is a difference of two lookups.
type gyroIntegral struct {
	t, ix, iy []float64
}

func newGyroIntegral(imu [][]float64) *gyroIntegral {
	g := &gyroIntegral{t: make([]float64, len(imu)), ix: make([]float64, len(imu)), iy: make([]float64, len(imu))}
	for i, s := range imu {
		g.t[i] = s[imuT]
		if i > 0 {
			dt := (s[imuT] - imu[i-1][imuT]) / 1000
			g.ix[i] = g.ix[i-1] + dt*(s[imuGX]+imu[i-1][imuGX])/2
			g.iy[i] = g.iy[i-1] + dt*(s[imuGY]+imu[i-1][imuGY])/2
		}
	}
	return g
}

// at returns the integrals at time t (linear interpolation, clamped).
func (g *gyroIntegral) at(t float64) (float64, float64) {
	n := len(g.t)
	if t <= g.t[0] {
		return g.ix[0], g.iy[0]
	}
	if t >= g.t[n-1] {
		return g.ix[n-1], g.iy[n-1]
	}
	i := sort.SearchFloat64s(g.t, t) // g.t[i-1] < t <= g.t[i]
	t0, t1 := g.t[i-1], g.t[i]
	w := 0.0
	if t1 > t0 {
		w = (t - t0) / (t1 - t0)
	}
	return g.ix[i-1] + w*(g.ix[i]-g.ix[i-1]), g.iy[i-1] + w*(g.iy[i]-g.iy[i-1])
}

// predictedShift is the image shift (px) that the phone's rotation between
// t0 and t1 causes for a distant point, in the upright front-camera image
// (unmirrored, x right, y down). With device axes x right, y up, z toward
// the user, and the front camera looking along +z: u' = f*wy, v' = -f*wx.
func (g *gyroIntegral) predictedShift(t0, t1, f float64) (float64, float64) {
	x0, y0 := g.at(t0)
	x1, y1 := g.at(t1)
	return f * (y1 - y0), -f * (x1 - x0)
}

type sweepPair struct {
	t0, t1         float64
	faceDX, faceDY float64
	bgDX, bgDY     float64
	bgOK           bool
}

func sweepPairs(tr NativeTrace, th NativeThresholds) []sweepPair {
	var out []sweepPair
	for i := 1; i < len(tr.Frames); i++ {
		a, b := tr.Frames[i-1], tr.Frames[i]
		if a[frT] < tr.Sweep[0] || b[frT] > tr.Sweep[1] {
			continue
		}
		dt := b[frT] - a[frT]
		if dt <= 0 || dt > 200 {
			continue
		}
		out = append(out, sweepPair{
			t0: a[frT], t1: b[frT],
			faceDX: b[frFaceX] - a[frFaceX], faceDY: b[frFaceY] - a[frFaceY],
			bgDX: b[frBgDX], bgDY: b[frBgDY],
			bgOK: b[frBgQ] >= th.MinBgQuality,
		})
	}
	return out
}

// fit returns the Pearson r of measured against predicted and the gain
// (least-squares slope through the origin).
func fit(meas, pred []float64) (r, gain float64) {
	n := float64(len(meas))
	if n < 3 {
		return 0, 0
	}
	var sm, sp float64
	for i := range meas {
		sm += meas[i]
		sp += pred[i]
	}
	mm, mp := sm/n, sp/n
	var cov, vm, vp, mpd, pp float64
	for i := range meas {
		dm, dp := meas[i]-mm, pred[i]-mp
		cov += dm * dp
		vm += dm * dm
		vp += dp * dp
		mpd += meas[i] * pred[i]
		pp += pred[i] * pred[i]
	}
	if vm == 0 || vp == 0 || pp == 0 {
		return 0, 0
	}
	return cov / math.Sqrt(vm*vp), mpd / pp
}

// series builds measured/predicted vectors (x values then y values).
func series(pairs []sweepPair, g *gyroIntegral, f, lag float64, sx, sy float64, useBg bool) (meas, pred []float64) {
	var mx, my, px, py []float64
	for _, p := range pairs {
		var dx, dy float64
		if useBg {
			if !p.bgOK {
				continue
			}
			dx, dy = p.bgDX, p.bgDY
		} else {
			dx, dy = p.faceDX, p.faceDY
		}
		ux, uy := g.predictedShift(p.t0+lag, p.t1+lag, f)
		mx, my = append(mx, dx), append(my, dy)
		px, py = append(px, sx*ux), append(py, sy*uy)
	}
	return append(mx, my...), append(px, py...)
}

func checkRotation(tr NativeTrace, g *gyroIntegral, th NativeThresholds, rep *MotionReport) {
	pairs := sweepPairs(tr, th)
	rep.SweepPairs = len(pairs)
	var ss float64
	n := 0
	for _, s := range tr.IMU {
		if s[imuT] >= tr.Sweep[0] && s[imuT] <= tr.Sweep[1] {
			ss += s[imuGX]*s[imuGX] + s[imuGY]*s[imuGY]
			n++
		}
	}
	if n > 0 {
		rep.SweepRate = round3(math.Sqrt(ss / float64(n)))
	}
	if len(pairs) < th.MinSweepPairs || rep.SweepRate < th.MinSweepRate {
		rep.Rotation = CheckInconclusive
		return
	}
	// The background is the cleaner rotation signal when it has texture;
	// a bare wall falls back to the face (the head is asked to stay still).
	bgN := 0
	for _, p := range pairs {
		if p.bgOK {
			bgN++
		}
	}
	useBg := bgN >= th.MinSweepPairs
	bestR, bestGain, bestLag := -2.0, 0.0, 0.0
	best := [2]int{1, 1}
	signs := []float64{1}
	if th.FitSigns {
		signs = []float64{1, -1}
	}
	for _, sx := range signs {
		for _, sy := range signs {
			for lag := -th.MaxLagMS; lag <= th.MaxLagMS; lag += 5 {
				meas, pred := series(pairs, g, tr.Device.FocalPx, lag, sx, sy, useBg)
				r, gain := fit(meas, pred)
				if r > bestR {
					bestR, bestGain, bestLag = r, gain, lag
					best = [2]int{int(sx), int(sy)}
				}
			}
		}
	}
	rep.RotationR, rep.RotationGain, rep.RotationLagMS, rep.Signs = round3(bestR), round3(bestGain), bestLag, best
	lo, hi := th.MinGain, th.MaxGain
	if !useBg {
		lo, hi = th.MinFaceGain, th.MaxFaceGain
	}
	rep.PlainBackground = !useBg
	if !useBg && bestGain < lo {
		// Face-only and the face barely moved: the phone orbited the head,
		// which keeps the face centred whatever the rotation. Cannot judge.
		rep.Rotation = CheckInconclusive
		return
	}
	if bestR >= th.MinRotationR && bestGain >= lo && bestGain <= hi {
		rep.Rotation = CheckPass
	} else {
		rep.Rotation = CheckFail
	}
}

func checkParallax(tr NativeTrace, g *gyroIntegral, th NativeThresholds, rep *MotionReport) {
	pairs := sweepPairs(tr, th)
	sx, sy := float64(rep.Signs[0]), float64(rep.Signs[1])
	fm, fp := series(pairs, g, tr.Device.FocalPx, rep.RotationLagMS, sx, sy, false)
	bm, bp := series(pairs, g, tr.Device.FocalPx, rep.RotationLagMS, sx, sy, true)
	if len(bm)/2 < th.MinSweepPairs {
		rep.Parallax = CheckInconclusive // no usable background texture
		return
	}
	_, gf := fit(fm, fp)
	_, gb := fit(bm, bp)
	rep.FaceGain, rep.BgGain = round3(gf), round3(gb)
	den := math.Max(math.Abs(gf), math.Abs(gb))
	if den == 0 {
		rep.Parallax = CheckInconclusive
		return
	}
	rep.ParallaxDiff = round3(math.Abs(gf-gb) / den)
	if rep.ParallaxDiff >= th.MinParallax {
		rep.Parallax = CheckPass
	} else {
		rep.Parallax = CheckFail
	}
}

// flashExpected is the chroma direction each colour pushes a lit surface.
var flashExpected = [3][3]float64{
	{2.0 / 3, -1.0 / 3, -1.0 / 3},
	{-1.0 / 3, 2.0 / 3, -1.0 / 3},
	{-1.0 / 3, -1.0 / 3, 2.0 / 3},
}

// colourAt returns the flash colour shown at time t, or -1 outside.
func colourAt(times []float64, colours []int, t float64) int {
	for k := 0; k < len(colours) && k+1 < len(times); k++ {
		if t >= times[k] && t < times[k+1] {
			return colours[k]
		}
	}
	return -1
}

func chroma(r, g, b float64) ([3]float64, bool) {
	s := r + g + b
	if s < 15 { // too dark to read a colour
		return [3]float64{}, false
	}
	return [3]float64{r / s, g / s, b / s}, true
}

func checkFlash(tr NativeTrace, colours []int, th NativeThresholds, rep *MotionReport) {
	if len(colours) == 0 || len(tr.Flash) != len(colours)+1 {
		return
	}
	bestR := -2.0
	var bestAmp, bestBg, bestLag float64
	bestN := 0
	for lag := 0.0; lag <= th.MaxFlashLagMS; lag += 10 {
		var face, bg, model [][3]float64
		for _, f := range tr.Frames {
			c := colourAt(tr.Flash, colours, f[frT]-lag)
			if c < 0 {
				continue
			}
			fc, ok1 := chroma(f[frFaceR], f[frFaceG], f[frFaceB])
			bc, ok2 := chroma(f[frBgR], f[frBgG], f[frBgB])
			if !ok1 || !ok2 {
				continue
			}
			face, bg, model = append(face, fc), append(bg, bc), append(model, flashExpected[c])
		}
		if len(face) < th.MinFlashFrames {
			continue
		}
		r, amp := chromaFit(face, model)
		_, bgAmp := chromaFit(bg, model)
		if r > bestR {
			bestR, bestAmp, bestBg, bestLag, bestN = r, amp, bgAmp, lag, len(face)
		}
	}
	if bestN == 0 {
		return // inconclusive: too few lit frames
	}
	rep.FlashR, rep.FlashAmp, rep.FlashBgAmp, rep.FlashLagMS = round3(bestR), round4(bestAmp), round4(bestBg), bestLag
	switch {
	case bestAmp < th.MinFlashAmp:
		// The face barely changed colour: bright room light swamps the
		// screen. Not evidence either way.
		rep.Flash = CheckInconclusive
	case bestR >= th.MinFlashR && bestBg <= th.MaxFlashBgRatio*bestAmp:
		rep.Flash = CheckPass
	default:
		rep.Flash = CheckFail
	}
}

// chromaFit correlates mean-removed chroma with the expected direction,
// over all three channels.
func chromaFit(obs, model [][3]float64) (r, amp float64) {
	var mean [3]float64
	for _, o := range obs {
		for c := 0; c < 3; c++ {
			mean[c] += o[c]
		}
	}
	var mm [3]float64
	for _, m := range model {
		for c := 0; c < 3; c++ {
			mm[c] += m[c]
		}
	}
	n := float64(len(obs))
	var meas, pred []float64
	for i := range obs {
		for c := 0; c < 3; c++ {
			meas = append(meas, obs[i][c]-mean[c]/n)
			pred = append(pred, model[i][c]-mm[c]/n)
		}
	}
	return fit(meas, pred)
}

// tremorShare is the fraction of gyro power (x and y, 1-20 Hz) that lies in
// 6-14 Hz, over the samples outside the sweep.
func tremorShare(tr NativeTrace) float64 {
	var t, x, y []float64
	for _, s := range tr.IMU {
		if s[imuT] >= tr.Sweep[0] && s[imuT] <= tr.Sweep[1] {
			continue
		}
		t, x, y = append(t, s[imuT]), append(x, s[imuGX]), append(y, s[imuGY])
	}
	if len(t) < 64 {
		return 0
	}
	dur := (t[len(t)-1] - t[0]) / 1000
	if dur <= 0 {
		return 0
	}
	var band, total float64
	for hz := 1.0; hz <= 20; hz += 0.5 {
		p := dftPower(t, x, hz) + dftPower(t, y, hz)
		total += p
		if hz >= 6 && hz <= 14 {
			band += p
		}
	}
	if total == 0 {
		return 0
	}
	return band / total
}

func dftPower(t, v []float64, hz float64) float64 {
	var mean float64
	for _, x := range v {
		mean += x
	}
	mean /= float64(len(v))
	var re, im float64
	for i := range v {
		a := 2 * math.Pi * hz * t[i] / 1000
		re += (v[i] - mean) * math.Cos(a)
		im += (v[i] - mean) * math.Sin(a)
	}
	return re*re + im*im
}

func round3(x float64) float64 { return math.Round(x*1000) / 1000 }
func round4(x float64) float64 { return math.Round(x*10000) / 10000 }
