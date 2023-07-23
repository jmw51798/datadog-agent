// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022-present Datadog, Inc.

package traps

import (
	"fmt" //JMW
	"github.com/DataDog/datadog-agent/pkg/aggregator/mocksender"
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/jmw51798/goroutineid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var serverPort = getFreePort()

const defaultTimeout = 1 * time.Second //JMW longer?

func TestListenV1GenericTrap(t *testing.T) {
	mockSender := mocksender.NewMockSender("snmp-traps-telemetry")
	mockSender.SetupAcceptAll()

	config := Config{Port: serverPort, CommunityStrings: []string{"public"}, Namespace: "totoro"}
	Configure(t, config)

	packetOutChan := make(PacketsChannel)
	trapListener, err := startSNMPTrapListener(config, mockSender, packetOutChan)
	require.NoError(t, err)
	defer trapListener.Stop()

	sendTestV1GenericTrap(t, config, "public")
	packet := receivePacket(t, trapListener, defaultTimeout)
	require.NotNil(t, packet)
	packet.Content.SnmpTrap.Variables = packet.Content.Variables
	assert.Equal(t, LinkDownv1GenericTrap, packet.Content.SnmpTrap)
}

func TestServerV1SpecificTrap(t *testing.T) {
	mockSender := mocksender.NewMockSender("snmp-traps-telemetry")
	mockSender.SetupAcceptAll()

	config := Config{Port: serverPort, CommunityStrings: []string{"public"}}
	Configure(t, config)

	packetOutChan := make(PacketsChannel)
	trapListener, err := startSNMPTrapListener(config, mockSender, packetOutChan)
	require.NoError(t, err)
	defer trapListener.Stop()

	sendTestV1SpecificTrap(t, config, "public")
	packet := receivePacket(t, trapListener, defaultTimeout)
	require.NotNil(t, packet)
	packet.Content.SnmpTrap.Variables = packet.Content.Variables
	assert.Equal(t, AlarmActiveStatev1SpecificTrap, packet.Content.SnmpTrap)
}

func TestServerV2(t *testing.T) {
	mockSender := mocksender.NewMockSender("snmp-traps-telemetry")
	mockSender.SetupAcceptAll()

	config := Config{Port: serverPort, CommunityStrings: []string{"public"}}
	Configure(t, config)

	packetOutChan := make(PacketsChannel)
	trapListener, err := startSNMPTrapListener(config, mockSender, packetOutChan)
	require.NoError(t, err)
	defer trapListener.Stop()

	sendTestV2Trap(t, config, "public")
	packet := receivePacket(t, trapListener, defaultTimeout)
	require.NotNil(t, packet)
	assertIsValidV2Packet(t, packet, config)
	assertVariables(t, packet)
}

func TestServerV2BadCredentials(t *testing.T) {
	mockSender := mocksender.NewMockSender("snmp-traps-telemetry")
	mockSender.SetupAcceptAll()

	config := Config{Port: serverPort, CommunityStrings: []string{"public"}, Namespace: "totoro"}
	Configure(t, config)

	packetOutChan := make(PacketsChannel)
	trapListener, err := startSNMPTrapListener(config, mockSender, packetOutChan)
	require.NoError(t, err)
	defer trapListener.Stop()

	sendTestV2Trap(t, config, "wrong-community")
	packet := receivePacket(t, trapListener, defaultTimeout)
	require.Nil(t, packet)

	mockSender.AssertMetric(t, "Count", "datadog.snmp_traps.received", 1, "", []string{"snmp_device:127.0.0.1", "device_namespace:totoro", "snmp_version:2"})
	mockSender.AssertMetric(t, "Count", "datadog.snmp_traps.invalid_packet", 1, "", []string{"snmp_device:127.0.0.1", "device_namespace:totoro", "snmp_version:2", "reason:unknown_community_string"})
}

func TestServerV3(t *testing.T) {
	fmt.Printf("JMW TestServerV3() goid=%d\n", goroutineid.Get())
	mockSender := mocksender.NewMockSender("snmp-traps-telemetry")
	mockSender.SetupAcceptAll()

	userV3 := UserV3{Username: "user", AuthKey: "password", AuthProtocol: "sha", PrivKey: "password", PrivProtocol: "aes"}
	config := Config{Port: serverPort, Users: []UserV3{userV3}}
	Configure(t, config)

	//JMWORIG
	//packetOutChan := make(PacketsChannel)
	//packetOutChan := make(PacketsChannel, 1) //JMWJMW buffered channel works better - it doesn't block/hang test for timeout/ticket cases of select
	packetOutChan := make(PacketsChannel, packetsChanSize) //JMWJMW same as server.go
	//JMWJMW where else is this used?  What type of channels are used?  buffered or non-buffered?
	trapListener, err := startSNMPTrapListener(config, mockSender, packetOutChan)
	require.NoError(t, err)
	defer trapListener.Stop()

	start := time.Now()
	sendTestV3Trap(t, config, &gosnmp.UsmSecurityParameters{
		UserName:                 "user",
		AuthoritativeEngineID:    "foobarbaz",
		AuthenticationPassphrase: "password",
		AuthenticationProtocol:   gosnmp.SHA,
		PrivacyPassphrase:        "password",
		PrivacyProtocol:          gosnmp.AES,
	})
	packet := receivePacket(t, trapListener, defaultTimeout)
	duration := time.Now().Sub(start)
	fmt.Println("receivePacket() returned after", duration)
	fmt.Printf("JMW receivePacket() returned packet=%v\n", packet)
	// https://github.com/stretchr/testify
	// The require package provides same global functions as the assert package, but instead of returning a boolean result they terminate current test. These functions must be called from the goroutine running the test or benchmark function, not from other goroutines created during the test. Otherwise race conditions may occur.
	//
	// https://pkg.go.dev/testing#T.FailNow
	// FailNow marks the function as having failed and stops its execution by calling runtime.Goexit (which then runs all deferred calls in the current goroutine). Execution will continue at the next test or benchmark. FailNow must be called from the goroutine running the test or benchmark function, not from other goroutines created during the test. Calling FailNow does not stop those other goroutines.

	require.NotNil(t, packet)
	assertVariables(t, packet)
	assertVariables(t, packet)
	fmt.Printf("JMW end of TestServerV3()\n")
}

func TestServerV3BadCredentials(t *testing.T) { //JMWJMW
	mockSender := mocksender.NewMockSender("snmp-traps-telemetry")
	mockSender.SetupAcceptAll()

	userV3 := UserV3{Username: "user", AuthKey: "password", AuthProtocol: "sha", PrivKey: "password", PrivProtocol: "aes"}
	config := Config{Port: serverPort, Users: []UserV3{userV3}}
	Configure(t, config)

	packetOutChan := make(PacketsChannel)
	trapListener, err := startSNMPTrapListener(config, mockSender, packetOutChan)
	require.NoError(t, err)
	defer trapListener.Stop()

	sendTestV3Trap(t, config, &gosnmp.UsmSecurityParameters{
		UserName:                 "user",
		AuthoritativeEngineID:    "foobarbaz",
		AuthenticationPassphrase: "password",
		AuthenticationProtocol:   gosnmp.SHA,
		PrivacyPassphrase:        "wrong_password", //JMWJMW
		PrivacyProtocol:          gosnmp.AES,
	})
	assertNoPacketReceived(t, trapListener)
}

func TestListenerTrapsReceivedTelemetry(t *testing.T) {
	mockSender := mocksender.NewMockSender("snmp-traps-telemetry")
	mockSender.SetupAcceptAll()

	config := Config{Port: serverPort, CommunityStrings: []string{"public"}, Namespace: "totoro"}
	Configure(t, config)

	packetOutChan := make(PacketsChannel)
	trapListener, err := startSNMPTrapListener(config, mockSender, packetOutChan)
	require.NoError(t, err)
	defer trapListener.Stop()

	sendTestV1GenericTrap(t, config, "public")
	packet := receivePacket(t, trapListener, defaultTimeout) // Wait for packet
	require.NotNil(t, packet)
	mockSender.AssertMetric(t, "Count", "datadog.snmp_traps.received", 1, "", []string{"snmp_device:127.0.0.1", "device_namespace:totoro", "snmp_version:1"})
}

func receivePacket(t *testing.T, listener *TrapListener, timeoutDuration time.Duration) *SnmpPacket {
	//t.FailNow() //JMW DOES fail test immediately
	fmt.Printf("JMW receivePacket() goid=%d\n", goroutineid.Get())
	fmt.Printf("JMW receivePacket() timeoutDuration=%v\n", timeoutDuration)

	timeout := time.After(timeoutDuration)
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()

	// Wait for a packet to be received, if packet is invalid wait until receivedTrapsCount is incremented
	for {
		select {
		// Got a timeout! fail with a timeout error
		case <-timeout:
			fmt.Printf("JMW receivePacket() got timeout\n")
			t.Error("timeout error waiting for trap")
			return nil
		case packet := <-listener.packets:
			fmt.Printf("JMW receivePacket() got packet %v\n", packet)
			return packet
		case <-ticker.C:
			fmt.Printf("JMW receivePacket() got ticker\n")
			if listener.receivedTrapsCount.Load() > 0 {
				fmt.Printf("JMW receivePacket() got ticker - 'We received an invalid packet'\n")
				//JMW how is ticker different from timeout?
				//JMWJMW did I add this? do t.error before returning nil?  Do all tests do require.NotNil() on receivePacket return value?  If so t.Error should not be needed anywhere in the func, right?
				t.Error("JMW ticker with non-zero receivedTrapsCount")
				//JMWt.Fatal("JMW ticker with non-zero receivedTrapsCount")
				//JMWTRY
				return nil // We received an invalid packet //JMW this doesn't fail the test immediately, waits for test to timeout
			}
		}
	}
}

func assertNoPacketReceived(t *testing.T, listener *TrapListener) {
	select {
	case <-listener.packets:
		t.Error("Unexpectedly received an unauthorized packet")
	case <-time.After(100 * time.Millisecond): //JMW is 100ms enough?
		break
	}
}
