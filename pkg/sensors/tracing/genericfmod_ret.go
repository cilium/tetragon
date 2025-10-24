package tracing

import (
	"path"

	"github.com/cilium/tetragon/pkg/config"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/program"
)

var fmodretMap map[string]*program.Program

func getFmodRetProg(attachFunc string) (*program.Program, *program.Map) {
	var fmodret *program.Program
	var ok bool

	if fmodretMap == nil {
		fmodretMap = make(map[string]*program.Program)
	}

	loadProgName, _ := config.GenericKprobeObjs(false)

	if fmodret, ok = fmodretMap[attachFunc]; !ok {

		fmodret = program.Builder(
			path.Join(option.Config.HubbleLib, loadProgName),
			attachFunc,
			"fmod_ret/security_task_prctl",
			"fmod_ret/"+attachFunc,
			"generic_fmod_ret")

		fmodret.PinPath = "fmod_ret/" + attachFunc

		fmodretmap := program.MapBuilder("override_tasks", fmodret)
		fmodretmap.PinPath = path.Join("fmod_ret/", attachFunc, "override_tasks")

		fmodretMap[attachFunc] = fmodret
	}
	return fmodret, fmodret.PinMap["override_tasks"]
}

func deleteFmodRetProg(attachFunc string) {
	var fmodret *program.Program
	var ok bool

	if fmodretMap == nil {
		return
	}
	if fmodret, ok = fmodretMap[attachFunc]; !ok {
		return
	}
	if !fmodret.LoadState.IsLoaded() {
		delete(fmodretMap, attachFunc)
	}
}
