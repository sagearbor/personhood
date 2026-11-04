package fuzzyextractorselfie

import (
	"encoding/json"
	"math"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
)

// A small physical simulator of the native ceremony, to test motion.go
// against honest captures and against attacks. Every number here is a
// modelling assumption, not a measurement: the false-reject and
// false-accept rates it reports are for this model only. Recorded traces
// from real phones go in testdata/native-traces (see TestNativeTraces_Recorded).

type simOpts struct {
	seed int64
	// Scene.
	lever      float64 // m: translation per radian of rotation (hand pivot)
	faceDepth  float64 // m
	bgDepth    float64 // m
	bgTexture  float64 // bgQ reported per frame
	flashAmp   float64 // face chroma change per unit colour
	flashBgAmp float64
	flashLag   float64 // ms, display to camera
	clockSkew  float64 // ms, camera timestamps vs IMU
	sweepAmp   float64 // rad
	gyroNoise  float64 // rad/s
	trackNoise float64 // px
	headWobble float64 // px, head motion during the sweep
	imuHz      float64
	still      bool // phone does not move at all (tripod / naive script)
}

func honestOpts(r *rand.Rand, seed int64) simOpts {
	o := simOpts{
		seed:       seed,
		lever:      (0.08 + r.Float64()*0.32) * float64(1-2*r.Intn(2)),
		faceDepth:  0.25 + r.Float64()*0.2,
		bgDepth:    1 + r.Float64()*3,
		bgTexture:  0.6,
		flashAmp:   0.01 + r.Float64()*0.03,
		flashLag:   40 + r.Float64()*110,
		clockSkew:  -20 + r.Float64()*40,
		sweepAmp:   0.12 + r.Float64()*0.25,
		gyroNoise:  0.005 + r.Float64()*0.015,
		trackNoise: 0.3 + r.Float64()*0.7,
		headWobble: r.Float64() * 4,
		imuHz:      []float64{100, 200, 400}[r.Intn(3)],
	}
	o.flashBgAmp = o.flashAmp * (0.03 + r.Float64()*0.15)
	if r.Float64() < 0.2 { // a bare wall behind the person
		o.bgTexture = 0.1
	}
	if r.Float64() < 0.3 { // daylight: the screen barely lights the face
		o.flashAmp = 0.002 + r.Float64()*0.004
		o.flashBgAmp = o.flashAmp * 0.1
	}
	return o
}

const (
	simFocal    = 500.0
	simSweep0   = 2000.0
	simSweep1   = 5000.0
	simFlash0   = 5300.0
	simEnd      = 8000.0
	simFrameDT  = 33.3
	simFaceCX   = 240.0
	simFaceCY   = 300.0
	simFaceSize = 200.0
)

// camera pose: rotation angles (rad) about device x and y at time t (ms).
type pose func(t float64) (ax, ay float64)

func simPose(r *rand.Rand, o simOpts) pose {
	if o.still {
		return func(float64) (float64, float64) { return 0, 0 }
	}
	type comp struct{ amp, hz, ph float64 }
	mk := func(n int, amp float64, lo, hi float64) []comp {
		out := make([]comp, n)
		for i := range out {
			out[i] = comp{amp * (0.4 + r.Float64()*0.6), lo + r.Float64()*(hi-lo), r.Float64() * 2 * math.Pi}
		}
		return out
	}
	swX, swY := mk(2, o.sweepAmp*0.4, 0.4, 1.4), mk(3, o.sweepAmp, 0.4, 1.4)
	trX, trY := mk(2, 0.0015, 7, 12), mk(2, 0.0015, 7, 12)
	drX, drY := mk(1, 0.01, 0.1, 0.4), mk(1, 0.01, 0.1, 0.4)
	sum := func(cs []comp, t float64) float64 {
		s := 0.0
		for _, c := range cs {
			s += c.amp * math.Sin(2*math.Pi*c.hz*t/1000+c.ph)
		}
		return s
	}
	env := func(t float64) float64 { // sweep envelope, smooth on and off
		if t < simSweep0 || t > simSweep1 {
			return 0
		}
		return math.Pow(math.Sin(math.Pi*(t-simSweep0)/(simSweep1-simSweep0)), 2)
	}
	return func(t float64) (float64, float64) {
		e := env(t)
		return e*sum(swX, t) + sum(trX, t) + sum(drX, t), e*sum(swY, t) + sum(trY, t) + sum(drY, t)
	}
}

// simulate builds one capture. The same seed gives the same capture.
func simulate(o simOpts, colours []int) NativeTrace {
	r := rand.New(rand.NewSource(o.seed))
	p := simPose(r, o)
	tr := NativeTrace{
		Device: NativeDevice{Model: "sim", SDK: 34, Gyro: true, Clock: "realtime", FocalPx: simFocal, Width: 480, Height: 640},
		Sweep:  [2]float64{simSweep0, simSweep1},
	}
	// IMU: analytic derivative of the pose plus noise and bias.
	bx, by := (r.Float64()-0.5)*0.01, (r.Float64()-0.5)*0.01
	for t := 0.0; t <= simEnd; t += 1000 / o.imuHz {
		x0, y0 := p(t - 0.5)
		x1, y1 := p(t + 0.5)
		gx := (x1-x0)*1000 + bx + r.NormFloat64()*o.gyroNoise
		gy := (y1-y0)*1000 + by + r.NormFloat64()*o.gyroNoise
		tr.IMU = append(tr.IMU, []float64{t, gx, gy, r.NormFloat64() * o.gyroNoise, r.NormFloat64() * 0.05, 9.81 + r.NormFloat64()*0.05, r.NormFloat64() * 0.05})
	}
	// Flash schedule.
	for k := 0; k <= len(colours); k++ {
		tr.Flash = append(tr.Flash, simFlash0+float64(k)*DefaultFlashSegmentMS+r.Float64()*4)
	}
	// Image position of a point at depth z for camera pose at t (x right, y down).
	img := func(t, z float64) (float64, float64) {
		ax, ay := p(t)
		k := 1 + o.lever/z
		return simFocal * ay * k, -simFocal * ax * k
	}
	headPh := r.Float64() * 6
	head := func(t float64) float64 { return o.headWobble * math.Sin(2*math.Pi*0.7*t/1000+headPh) }
	skin := [3]float64{0.44, 0.31, 0.25}
	wall := [3]float64{0.36, 0.34, 0.30}
	var prevBg [2]float64
	for i := 0; ; i++ {
		t := float64(i)*simFrameDT + r.Float64()*2
		if t > simEnd {
			break
		}
		fx, fy := img(t, o.faceDepth)
		bgx, bgy := img(t, o.bgDepth)
		dbx, dby := bgx-prevBg[0], bgy-prevBg[1]
		prevBg = [2]float64{bgx, bgy}
		if i == 0 {
			dbx, dby = 0, 0
		}
		c := colourAt(tr.Flash, colours, t-o.flashLag)
		face, bg := skin, wall
		for ch := 0; ch < 3; ch++ {
			if c >= 0 {
				face[ch] += o.flashAmp * flashExpected[c][ch]
				bg[ch] += o.flashBgAmp * flashExpected[c][ch]
			}
			face[ch] += r.NormFloat64() * 0.002
			bg[ch] += r.NormFloat64() * 0.002
		}
		bgNoise := o.trackNoise
		if o.bgTexture < 0.3 {
			bgNoise *= 6
		}
		tr.Frames = append(tr.Frames, []float64{
			t + o.clockSkew,
			simFaceCX + fx + head(t) + r.NormFloat64()*o.trackNoise,
			simFaceCY + fy + r.NormFloat64()*o.trackNoise,
			simFaceSize,
			dbx + r.NormFloat64()*bgNoise, dby + r.NormFloat64()*bgNoise, o.bgTexture,
			face[0] * 450, face[1] * 450, face[2] * 450,
			bg[0] * 300, bg[1] * 300, bg[2] * 300,
		})
	}
	return tr
}

func testColours(seed int64) []int {
	lc := &LivenessConfig{Key: make([]byte, 32)}
	lc.Key[0] = byte(seed)
	lc.Key[1] = byte(seed >> 8)
	return lc.flashColours("tok", DefaultFlashColours)
}

func TestNativeTrace_HonestPasses(t *testing.T) {
	t.Parallel()
	r := rand.New(rand.NewSource(1))
	o := honestOpts(r, 1)
	o.bgTexture, o.flashAmp, o.flashBgAmp, o.lever = 0.6, 0.02, 0.002, 0.3
	cols := testColours(1)
	rep := AnalyzeNativeTrace(simulate(o, cols), cols, NativeThresholds{})
	if !rep.Pass || rep.Rotation != CheckPass || rep.Parallax != CheckPass || rep.Flash != CheckPass {
		t.Fatalf("honest capture: %+v", rep)
	}
	if rep.Signs != [2]int{1, 1} {
		t.Fatalf("signs = %v, want the derived +1,+1", rep.Signs)
	}
	if rep.Tremor < 0.3 {
		t.Fatalf("hand tremor share = %v, want most gyro power in 6-14 Hz outside the sweep", rep.Tremor)
	}
}

// Video replay: the frames come from another capture (another time, or a
// virtual camera), the IMU from this phone now.
func TestNativeTrace_VideoReplayWithoutMatchingIMU(t *testing.T) {
	t.Parallel()
	r := rand.New(rand.NewSource(2))
	cols := testColours(2)
	video := simulate(honestOpts(r, 20), cols)
	now := simulate(honestOpts(r, 21), cols)
	video.IMU = now.IMU
	rep := AnalyzeNativeTrace(video, cols, NativeThresholds{})
	if rep.Pass || rep.Reason != "native_motion_inconsistent" {
		t.Fatalf("replayed video with this phone's IMU: %+v", rep)
	}
}

// IMU replay: a recorded IMU stream played next to a different video.
func TestNativeTrace_IMUReplayWithMismatchedVideo(t *testing.T) {
	t.Parallel()
	r := rand.New(rand.NewSource(3))
	cols := testColours(3)
	recorded := simulate(honestOpts(r, 30), cols)
	video := simulate(honestOpts(r, 31), cols)
	video.IMU = recorded.IMU
	if rep := AnalyzeNativeTrace(video, cols, NativeThresholds{}); rep.Pass {
		t.Fatalf("IMU replay: %+v", rep)
	}
	// The right recording, but out of step by more than the lag window.
	shifted := simulate(honestOpts(rand.New(rand.NewSource(32)), 32), cols)
	for _, f := range shifted.Frames {
		f[frT] += 400
	}
	if rep := AnalyzeNativeTrace(shifted, cols, NativeThresholds{}); rep.Pass {
		t.Fatalf("IMU 400 ms out of step with the video: %+v", rep)
	}
}

// A real phone filming a screen or print: motion agrees (it is a real
// camera), but face and background sit at one depth and reflect the flash
// alike.
func TestNativeTrace_FlatScreenFailsDepth(t *testing.T) {
	t.Parallel()
	r := rand.New(rand.NewSource(4))
	o := honestOpts(r, 40)
	o.faceDepth, o.bgDepth, o.bgTexture, o.lever = 0.35, 0.35, 0.6, 0.1
	o.flashAmp, o.flashBgAmp = 0.012, 0.012
	cols := testColours(4)
	rep := AnalyzeNativeTrace(simulate(o, cols), cols, NativeThresholds{})
	if rep.Pass || rep.Reason != "native_depth_not_seen" || rep.Rotation != CheckPass {
		t.Fatalf("flat screen: %+v", rep)
	}
}

func TestNativeTrace_StillPhoneIsInconclusive(t *testing.T) {
	t.Parallel()
	o := honestOpts(rand.New(rand.NewSource(5)), 50)
	o.still = true
	cols := testColours(5)
	rep := AnalyzeNativeTrace(simulate(o, cols), cols, NativeThresholds{})
	if rep.Pass || rep.Reason != "native_sweep_too_small" {
		t.Fatalf("phone on a stand: %+v", rep)
	}
}

func TestNativeTrace_FlashWrongSequenceFails(t *testing.T) {
	t.Parallel()
	o := honestOpts(rand.New(rand.NewSource(6)), 60)
	o.flashAmp, o.flashBgAmp = 0.02, 0.001
	shown := testColours(6)
	issued := testColours(7) // the replay lit the face with another sequence
	if equalInts(shown, issued) {
		t.Skip("colour sequences collided")
	}
	rep := AnalyzeNativeTrace(simulate(o, shown), issued, NativeThresholds{})
	if rep.Flash == CheckPass {
		t.Fatalf("flash passed against the wrong sequence: %+v", rep)
	}
}

func TestNativeTrace_RejectsMalformed(t *testing.T) {
	t.Parallel()
	cols := testColours(8)
	base := simulate(honestOpts(rand.New(rand.NewSource(8)), 80), cols)
	cases := map[string]func(*NativeTrace){
		"no gyro":         func(tr *NativeTrace) { tr.Device.Gyro = false },
		"no focal":        func(tr *NativeTrace) { tr.Device.FocalPx = 0 },
		"short row":       func(tr *NativeTrace) { tr.Frames[3] = tr.Frames[3][:5] },
		"NaN":             func(tr *NativeTrace) { tr.IMU[3][1] = math.NaN() },
		"time backwards":  func(tr *NativeTrace) { tr.Frames[5][frT] = -1 },
		"empty sweep":     func(tr *NativeTrace) { tr.Sweep = [2]float64{10, 10} },
		"imu too slow":    func(tr *NativeTrace) { tr.IMU = tr.IMU[:len(tr.IMU)/40] },
		"too many frames": func(tr *NativeTrace) { tr.Frames = make([][]float64, maxTraceFrames+1) },
	}
	for name, mutate := range cases {
		b, _ := json.Marshal(base)
		var tr NativeTrace
		_ = json.Unmarshal(b, &tr)
		mutate(&tr)
		if rep := AnalyzeNativeTrace(tr, cols, NativeThresholds{}); rep.Pass {
			t.Errorf("%s: passed", name)
		}
	}
}

// TestNativeTrace_Rates is the Monte Carlo summary: honest captures across
// the modelled range (bare walls, daylight, pivots, phones) and each
// attack. Run with -v to see the numbers.
func TestNativeTrace_Rates(t *testing.T) {
	if testing.Short() {
		t.Skip("Monte Carlo")
	}
	t.Parallel()
	const n = 600
	r := rand.New(rand.NewSource(99))
	reasons := map[string]int{}
	rejects := 0
	for i := 0; i < n; i++ {
		seed := int64(1000 + i)
		cols := testColours(seed)
		rep := AnalyzeNativeTrace(simulate(honestOpts(r, seed), cols), cols, NativeThresholds{})
		if !rep.Pass {
			rejects++
			reasons[rep.Reason]++
		}
	}
	frr := float64(rejects) / n
	t.Logf("honest (simulated): false reject %.1f%% (%d/%d) %v", 100*frr, rejects, n, reasons)

	attacks := map[string]func(i int) (NativeTrace, []int){
		"video replay, live IMU": func(i int) (NativeTrace, []int) {
			cols := testColours(int64(i))
			v := simulate(honestOpts(r, int64(5000+i)), cols)
			v.IMU = simulate(honestOpts(r, int64(6000+i)), cols).IMU
			return v, cols
		},
		"flat screen on a real phone": func(i int) (NativeTrace, []int) {
			cols := testColours(int64(i))
			o := honestOpts(r, int64(7000+i))
			o.bgDepth = o.faceDepth + 0.05 // a screen or print with a little relief
			o.flashBgAmp = o.flashAmp * (0.8 + r.Float64()*0.4)
			return simulate(o, cols), cols
		},
		"still phone / scripted IMU": func(i int) (NativeTrace, []int) {
			cols := testColours(int64(i))
			o := honestOpts(r, int64(8000+i))
			o.still = true
			return simulate(o, cols), cols
		},
	}
	for name, mk := range attacks {
		accepted := 0
		for i := 0; i < n; i++ {
			tr, cols := mk(i)
			if AnalyzeNativeTrace(tr, cols, NativeThresholds{}).Pass {
				accepted++
			}
		}
		far := float64(accepted) / n
		t.Logf("attack %q (simulated): false accept %.1f%% (%d/%d)", name, 100*far, accepted, n)
		if far > 0.02 {
			t.Errorf("attack %q accepted %.1f%%", name, 100*far)
		}
	}
	// The model sends 20% of captures to a bare wall and 30% to daylight;
	// a capture with both has neither parallax nor flash and falls back
	// to the web strength (never a refusal). Most rejects are those.
	if frr > 0.15 {
		t.Errorf("honest false reject %.1f%% > 15%%", 100*frr)
	}
	if other := rejects - reasons["native_background_plain"] - reasons["native_depth_not_seen"]; other > n/100 {
		t.Errorf("%d honest captures rejected as inconsistent (want <= 1%%)", other)
	}
}

// TestNativeTraces_Recorded replays real captures. A file is the JSON
// {"expect":"pass"|"fail","colours":[...],"trace":{...}}; the wallet logs
// a trace in this shape with its debug switch on (see docs/selfie-anchor.md).
// None are recorded yet.
func TestNativeTraces_Recorded(t *testing.T) {
	files, _ := filepath.Glob("testdata/native-traces/*.json")
	if len(files) == 0 {
		t.Skip("no recorded traces in testdata/native-traces yet")
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var rec struct {
			Expect  string      `json:"expect"`
			Colours []int       `json:"colours"`
			Trace   NativeTrace `json:"trace"`
		}
		if err := json.Unmarshal(b, &rec); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		rep := AnalyzeNativeTrace(rec.Trace, rec.Colours, NativeThresholds{})
		if rep.Pass != (rec.Expect == "pass") {
			t.Errorf("%s: expect %s, got %+v", f, rec.Expect, rep)
		}
	}
}

func equalInts(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
