package tetragon

type IsGetEventsResponse_Event = isGetEventsResponse_Event

func (x *ProcessExec) Encapsulate() IsGetEventsResponse_Event {
	return &GetEventsResponse_ProcessExec{
		ProcessExec: x,
	}
}

func (x *ProcessExit) Encapsulate() IsGetEventsResponse_Event {
	return &GetEventsResponse_ProcessExit{
		ProcessExit: x,
	}
}

func (x *ProcessKprobe) Encapsulate() IsGetEventsResponse_Event {
	return &GetEventsResponse_ProcessKprobe{
		ProcessKprobe: x,
	}
}

func (x *ProcessTracepoint) Encapsulate() IsGetEventsResponse_Event {
	return &GetEventsResponse_ProcessTracepoint{
		ProcessTracepoint: x,
	}
}

func (x *Test) Encapsulate() IsGetEventsResponse_Event {
	return &GetEventsResponse_Test{
		Test: x,
	}
}

func (x *ProcessExec) SetProcess(p *Process) {
	x.Process = p
}

func (x *ProcessExit) SetProcess(p *Process) {
	x.Process = p
}

func (x *ProcessKprobe) SetProcess(p *Process) {
	x.Process = p
}

func (x *ProcessTracepoint) SetProcess(p *Process) {
	x.Process = p
}
