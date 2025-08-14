//! 混淆电路测试
//! 
//! 包含电路构造, 混淆器, 求值器等混淆电路相关测试

use mpc_api::garbled_circuits::*;

// ===== Circuit Tests =====

#[test]
fn test_circuit_creation() {
    let mut circuit = Circuit::new();
    
    let wire1 = circuit.add_input_wire();
    let wire2 = circuit.add_input_wire();
    let and_output = circuit.and_gate(wire1, wire2);
    circuit.add_output_wire(and_output);
    
    assert_eq!(circuit.input_wires.len(), 2);
    assert_eq!(circuit.output_wires.len(), 1);
    assert_eq!(circuit.gates.len(), 1);
    assert_eq!(circuit.gates[0].gate_type, GateType::And);
}

#[test]
fn test_adder_circuit() {
    let circuit = Circuit::create_adder(4);
    
    // 4-bit adder should have 8 input wires (4 for each number)
    assert_eq!(circuit.input_wires.len(), 8);
    
    // Should have 5 output wires (4 sum bits + 1 carry)
    assert_eq!(circuit.output_wires.len(), 5);
    
    // Should have multiple gates for the adder logic
    assert!(circuit.gates.len() > 0);
}