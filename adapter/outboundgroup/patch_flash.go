package outboundgroup

// Flash: whether the group's own disable-udp is set, apart from what its
// selection supports.
func (s *Selector) DisableUDP() bool { return s.disableUDP }

func (u *URLTest) DisableUDP() bool { return u.disableUDP }

func (f *Fallback) DisableUDP() bool { return f.disableUDP }

func (lb *LoadBalance) DisableUDP() bool { return lb.disableUDP }
