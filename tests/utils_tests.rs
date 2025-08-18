use mpc_api::utils::memory::*;

#[test]
fn test_secure_buffer_creation() {
    let buffer = SecureBuffer::new(1024).unwrap();
    assert_eq!(buffer.len(), 1024);
    assert!(!buffer.is_empty());
}

#[test]
fn test_secure_buffer_operations() {
    let mut buffer = SecureBuffer::new(32).unwrap();
    let test_data = b"hello world, this is test data!!"; // 32 bytes
    
    buffer.copy_from_slice(test_data).unwrap();
    
    let mut output = [0u8; 32];
    buffer.copy_to_slice(&mut output).unwrap();
    
    assert_eq!(&output[..], test_data);
}

#[test]
fn test_secure_zero() {
    let mut buffer = SecureBuffer::new(64).unwrap();
    let test_data = vec![0xAAu8; 64];
    
    buffer.copy_from_slice(&test_data).unwrap();
    buffer.secure_zero().unwrap();
    
    let result = buffer.as_slice();
    assert!(result.iter().all(|&b| b == 0));
}

#[test]
fn test_secure_compare() {
    let data1 = b"test data";
    let data2 = b"test data";
    let data3 = b"different";
    
    assert!(secure_compare(data1.as_ptr(), data2.as_ptr(), data1.len()));
    assert!(!secure_compare(data1.as_ptr(), data3.as_ptr(), data1.len()));
}

#[test]
fn test_stack_protector() {
    let protector = StackProtector::new();
    protector.check();  // 应该正常通过
    
    let id = protector.id();
    assert!(id > 0);
}

#[test]
fn test_constant_time_eq() {
    let buffer1 = SecureBuffer::from_slice(b"identical data").unwrap();
    let buffer2 = SecureBuffer::from_slice(b"identical data").unwrap();
    let buffer3 = SecureBuffer::from_slice(b"different data").unwrap();
    
    assert!(buffer1.constant_time_eq(&buffer2));
    assert!(!buffer1.constant_time_eq(&buffer3));
}

#[test]
fn test_memory_stats() {
    let _buffer = SecureBuffer::new(1024).unwrap();
    let stats = get_memory_stats();
    
    assert!(stats.secure_buffers > 0);
    assert!(stats.secure_bytes >= 1024);
    assert!(stats.page_size > 0);
}