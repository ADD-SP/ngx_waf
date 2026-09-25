//! A thin wrapper over the C API of libmodsecurity.
//!
//! The library is reachable through the C API (`msc_*` functions) of
//! `<modsecurity/modsecurity.h>`, which is what a server connector needs:
//! create an instance with a rule set, run the request phases of a
//! transaction, look at the intervention and let the library write its own
//! logs.
//!
//! The declarations below are written by hand instead of pulling a `-sys`
//! crate: the module only calls a dozen functions and none of them ever
//! changed since libmodsecurity 3.0.0, so the raw binding is smaller than the
//! dependency would be.  The library itself is linked by nginx, see
//! `ngx_http_waf_module_libs` in `config`.
//!
//! There is no response phase wrapper: the response headers and body are
//! intentionally not inspected (see `rust/README.md`).

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};

#[link(name = "modsecurity")]
extern "C" {
    fn msc_init() -> *mut c_void;
    fn msc_set_log_cb(instance: *mut c_void, callback: ModSecLogCb);
    fn msc_cleanup(instance: *mut c_void);

    fn msc_create_rules_set() -> *mut c_void;
    fn msc_rules_add_file(
        rules: *mut c_void,
        file: *const c_char,
        error: *mut *const c_char,
    ) -> c_int;
    fn msc_rules_add_remote(
        rules: *mut c_void,
        key: *const c_char,
        uri: *const c_char,
        error: *mut *const c_char,
    ) -> c_int;
    fn msc_rules_cleanup(rules: *mut c_void) -> c_int;

    fn msc_new_transaction(
        instance: *mut c_void,
        rules: *mut c_void,
        log_data: *mut c_void,
    ) -> *mut c_void;
    fn msc_new_transaction_with_id(
        instance: *mut c_void,
        rules: *mut c_void,
        id: *const c_char,
        log_data: *mut c_void,
    ) -> *mut c_void;
    fn msc_transaction_cleanup(transaction: *mut c_void);

    fn msc_process_connection(
        transaction: *mut c_void,
        client: *const c_char,
        client_port: c_int,
        server: *const c_char,
        server_port: c_int,
    ) -> c_int;
    fn msc_process_uri(
        transaction: *mut c_void,
        uri: *const c_char,
        method: *const c_char,
        http_version: *const c_char,
    ) -> c_int;
    fn msc_add_n_request_header(
        transaction: *mut c_void,
        key: *const u8,
        key_len: usize,
        value: *const u8,
        value_len: usize,
    ) -> c_int;
    fn msc_process_request_headers(transaction: *mut c_void) -> c_int;
    fn msc_append_request_body(transaction: *mut c_void, body: *const u8, size: usize) -> c_int;
    fn msc_process_request_body(transaction: *mut c_void) -> c_int;
    fn msc_update_status_code(transaction: *mut c_void, status: c_int) -> c_int;
    fn msc_intervention(transaction: *mut c_void, intervention: *mut Intervention) -> c_int;
    fn msc_process_logging(transaction: *mut c_void) -> c_int;
}

extern "C" {
    /// `src/ngx_http_waf_module.c`: writes one message of the library to the
    /// error log of the connection.
    fn ngx_http_waf_modsecurity_log(log: *mut c_void, message: *const c_char);

    /// The library hands the `url` and `log` of an intervention to the caller
    /// and does not own them anymore.
    fn free(pointer: *mut c_void);
}

/// `ModSecLogCb` of `<modsecurity/modsecurity.h>`.
type ModSecLogCb = Option<unsafe extern "C" fn(log: *mut c_void, data: *const c_char)>;

/// `ModSecurityIntervention` of `<modsecurity/intervention.h>`.
#[repr(C)]
struct Intervention {
    status: c_int,
    pause: c_int,
    url: *mut c_char,
    log: *mut c_char,
    disruptive: c_int,
}

impl Intervention {
    fn empty() -> Intervention {
        Intervention {
            status: 200,
            pause: 0,
            url: std::ptr::null_mut(),
            log: std::ptr::null_mut(),
            disruptive: 0,
        }
    }
}

/// What the library asks the server to do.
pub struct Verdict {
    pub status: u32,
    /// A redirection target, when the rule asked for one.
    pub url: Option<Vec<u8>>,
    /// The message of the rule that matched.
    pub log: Option<Vec<u8>>,
    pub disruptive: bool,
}

/// The library refused a call: the C API only reports success with `1` and
/// offers no message of its own, so the caller answers the internal error of
/// the request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModSecError;

impl std::fmt::Display for ModSecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the libmodsecurity call failed")
    }
}

impl std::error::Error for ModSecError {}

/// A `ModSecurity` instance and its rule set.
pub struct Instance {
    instance: *mut c_void,
    rules: *mut c_void,
}

impl Instance {
    /// Create the instance and load the rules of one `waf_modsecurity`
    /// directive.  `files` are its `file=` arguments, in the order they were
    /// written (the directive accepts more than one), the optional pair is the
    /// `remote_key=`/`remote_url=` one, added after the files.
    pub fn create(files: &[&[u8]], remote: Option<(&[u8], &[u8])>) -> Result<Instance, String> {
        // SAFETY: `msc_init()` takes no arguments and returns NULL or a live
        // instance owned by this wrapper.
        let instance = unsafe { msc_init() };
        if instance.is_null() {
            return Err("ngx_waf: msc_init() failed".to_string());
        }

        // SAFETY: the instance is live, the call returns NULL or a live rule
        // set owned by this wrapper.
        let rules = unsafe { msc_create_rules_set() };
        if rules.is_null() {
            // SAFETY: `instance` came from `msc_init()` and is not used again.
            unsafe { msc_cleanup(instance) };
            return Err("ngx_waf: msc_create_rules_set() failed".to_string());
        }

        let loaded = Instance { instance, rules };
        // SAFETY: the instance is live and the callback has the C signature.
        unsafe { msc_set_log_cb(loaded.instance, Some(modsecurity_log)) };

        for file in files {
            let file = CString::new(*file)
                .map_err(|_| "ngx_waf: the path of the rule file is invalid".to_string())?;
            let mut error: *const c_char = std::ptr::null();
            // SAFETY: the rule set is live, `file` is NUL terminated for the
            // call and `error` is a valid out-parameter.
            let result = unsafe { msc_rules_add_file(loaded.rules, file.as_ptr(), &mut error) };
            if result < 0 {
                return Err(format!("ngx_waf: {}", take_error(error)));
            }
        }

        if let Some((key, url)) = remote {
            let key =
                CString::new(key).map_err(|_| "ngx_waf: remote_key is invalid".to_string())?;
            let url =
                CString::new(url).map_err(|_| "ngx_waf: remote_url is invalid".to_string())?;
            let mut error: *const c_char = std::ptr::null();
            // SAFETY: the rule set is live and both strings are NUL terminated
            // for the call; `error` is a valid out-parameter.
            let result = unsafe {
                msc_rules_add_remote(loaded.rules, key.as_ptr(), url.as_ptr(), &mut error)
            };
            if result < 0 {
                return Err(format!("ngx_waf: {}", take_error(error)));
            }
        }

        Ok(loaded)
    }

    /// Start one transaction.  `id` is the value of
    /// `waf_modsecurity_transaction_id`, `None` when the directive is not
    /// configured (the library then generates one); `log` is
    /// `r->connection->log`, the data of the log callback.
    pub fn transaction(&self, id: Option<&[u8]>, log: *mut c_void) -> Option<Transaction> {
        let transaction = match id {
            Some(id) => {
                // `waf_modsecurity_transaction_id` is compiled with
                // `ngx_http_compile_complex_value_t::zero = 1`, so the length
                // of the value nginx hands over counts the terminating NUL.
                // The id is the text in front of that NUL.
                let id = match id.iter().position(|&byte| byte == 0) {
                    Some(end) => &id[..end],
                    None => id,
                };
                let id = CString::new(id).ok()?;
                // SAFETY: the instance and its rule set are alive, the id is
                // NUL terminated for the call.
                unsafe { msc_new_transaction_with_id(self.instance, self.rules, id.as_ptr(), log) }
            }
            // SAFETY: the instance and its rule set are alive until `Drop`.
            None => unsafe { msc_new_transaction(self.instance, self.rules, log) },
        };

        if transaction.is_null() {
            None
        } else {
            Some(Transaction { transaction })
        }
    }
}

impl Drop for Instance {
    fn drop(&mut self) {
        // SAFETY: both pointers came from the library and the instance is not
        // used after this call.
        unsafe {
            msc_rules_cleanup(self.rules);
            msc_cleanup(self.instance);
        }
    }
}

/// One `ModSecurity` transaction, alive from the access phase until nginx
/// destroys the request pool (which is after the log phase).
pub struct Transaction {
    transaction: *mut c_void,
}

impl Transaction {
    /// `msc_process_connection()`: the client and server endpoints.
    pub fn process_connection(
        &mut self,
        client: &[u8],
        client_port: u32,
        server: &[u8],
        server_port: u32,
    ) -> Result<(), ModSecError> {
        let client = CString::new(client).map_err(|_| ModSecError)?;
        let server = CString::new(server).map_err(|_| ModSecError)?;
        // SAFETY: the transaction is live until `Drop` and the two strings are
        // NUL terminated for the call.
        let result = unsafe {
            msc_process_connection(
                self.transaction,
                client.as_ptr(),
                client_port as c_int,
                server.as_ptr(),
                server_port as c_int,
            )
        };
        check_status(result)
    }

    /// `msc_process_uri()`.
    pub fn process_uri(
        &mut self,
        uri: &[u8],
        method: &[u8],
        http_version: &[u8],
    ) -> Result<(), ModSecError> {
        let uri = CString::new(uri).map_err(|_| ModSecError)?;
        let method = CString::new(method).map_err(|_| ModSecError)?;
        let http_version = CString::new(http_version).map_err(|_| ModSecError)?;
        // SAFETY: the transaction is live until `Drop` and the three strings
        // are NUL terminated for the call.
        let result = unsafe {
            msc_process_uri(
                self.transaction,
                uri.as_ptr(),
                method.as_ptr(),
                http_version.as_ptr(),
            )
        };
        check_status(result)
    }

    /// `msc_add_n_request_header()`, called once per header of the request.
    pub fn add_request_header(&mut self, key: &[u8], value: &[u8]) -> Result<(), ModSecError> {
        if key.is_empty() {
            return Ok(());
        }
        // SAFETY: the transaction is live until `Drop`, and the key and value
        // stay readable for the length the call is given.
        let result = unsafe {
            msc_add_n_request_header(
                self.transaction,
                key.as_ptr(),
                key.len(),
                value.as_ptr(),
                value.len(),
            )
        };
        check_status(result)
    }

    /// `msc_process_request_headers()`.
    pub fn process_request_headers(&mut self) -> Result<(), ModSecError> {
        // SAFETY: the transaction is live until `Drop`.
        check_status(unsafe { msc_process_request_headers(self.transaction) })
    }

    /// `msc_append_request_body()`.
    pub fn append_request_body(&mut self, body: &[u8]) -> Result<(), ModSecError> {
        // SAFETY: the transaction is live until `Drop` and `body` stays
        // readable for its length.
        check_status(unsafe {
            msc_append_request_body(self.transaction, body.as_ptr(), body.len())
        })
    }

    /// `msc_process_request_body()`.
    pub fn process_request_body(&mut self) -> Result<(), ModSecError> {
        // SAFETY: the transaction is live until `Drop`.
        check_status(unsafe { msc_process_request_body(self.transaction) })
    }

    /// `msc_update_status_code()`.
    pub fn update_status_code(&mut self, status: u32) -> Result<(), ModSecError> {
        // SAFETY: the transaction is live until `Drop`.
        check_status(unsafe { msc_update_status_code(self.transaction, status as c_int) })
    }

    /// `msc_intervention()`, `None` when the library has nothing to ask for.
    pub fn intervention(&mut self) -> Option<Verdict> {
        let mut intervention = Intervention::empty();
        // SAFETY: the transaction is live until `Drop` and `intervention` is a
        // zeroed out-parameter of the C struct layout.
        if unsafe { msc_intervention(self.transaction, &mut intervention) } <= 0 {
            return None;
        }

        let url = copy_and_free(intervention.url);
        let log = copy_and_free(intervention.log);

        Some(Verdict {
            status: intervention.status as u32,
            url,
            log,
            disruptive: intervention.disruptive != 0,
        })
    }

    /// `msc_process_logging()`: let the library write its audit log.  Called
    /// from the log phase of nginx.
    pub fn process_logging(&mut self) {
        // SAFETY: the transaction is live until `Drop`.
        unsafe {
            msc_process_logging(self.transaction);
        }
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        // SAFETY: `self.transaction` came from the library and is not used
        // after this call.
        unsafe { msc_transaction_cleanup(self.transaction) };
    }
}

/// The library treats `1` as success.
fn check_status(result: c_int) -> Result<(), ModSecError> {
    if result == 1 {
        Ok(())
    } else {
        Err(ModSecError)
    }
}

/// The messages of the library go to the error log of the connection.
unsafe extern "C" fn modsecurity_log(log: *mut c_void, message: *const c_char) {
    if log.is_null() || message.is_null() {
        return;
    }
    // SAFETY: both pointers come from the library and stay valid for the
    // duration of the callback.
    unsafe { ngx_http_waf_modsecurity_log(log, message) };
}

/// A string the library handed over and expects `free()` on.
///
/// The library allocates these with `strdup()`, so the caller owns them: the
/// guard is what says so, and it releases the string on every path out of the
/// function that took it.
struct OwnedCStr(*mut c_char);

impl OwnedCStr {
    /// Take the ownership of `pointer`, `None` when the library returned
    /// nothing.
    ///
    /// # Safety
    /// `pointer` must be NULL or a NUL terminated string the library
    /// allocated and handed over to the caller.
    unsafe fn new(pointer: *mut c_char) -> Option<OwnedCStr> {
        if pointer.is_null() {
            None
        } else {
            Some(OwnedCStr(pointer))
        }
    }

    /// The text of the string, without the terminating NUL.
    fn to_bytes(&self) -> &[u8] {
        // SAFETY: the guard only exists for a live string of the library.
        unsafe { CStr::from_ptr(self.0) }.to_bytes()
    }

    /// The text of the string as an owned `String`, invalid bytes included.
    fn to_text(&self) -> String {
        // SAFETY: see `to_bytes()`.
        unsafe { CStr::from_ptr(self.0) }
            .to_string_lossy()
            .into_owned()
    }
}

impl Drop for OwnedCStr {
    fn drop(&mut self) {
        // SAFETY: the pointer came from the library, which allocates these
        // strings with `strdup()` and expects the caller to `free()` them.
        unsafe { free(self.0 as *mut c_void) };
    }
}

/// Take the message of a failed `msc_rules_add_*()` call: it is allocated with
/// `strdup()` by the library, the caller frees it.
fn take_error(error: *const c_char) -> String {
    // SAFETY: the library promises a NUL terminated message it allocated with
    // `strdup()`, which the guard takes over.
    match unsafe { OwnedCStr::new(error as *mut c_char) } {
        Some(message) => message.to_text(),
        None => "(no error message)".to_string(),
    }
}

/// Copy the string of an intervention, then release it (the caller owns it).
fn copy_and_free(pointer: *mut c_char) -> Option<Vec<u8>> {
    // SAFETY: the library promises a NUL terminated string it allocated and
    // handed over to the caller, which owns it now.
    let text = unsafe { OwnedCStr::new(pointer) }?;

    Some(text.to_bytes().to_vec())
}

/// Serialise the tests that use libmodsecurity.
///
/// The library must not be entered by two threads while instances come and go:
/// its constructor and its destructor call `curl_global_init()` and
/// `curl_global_cleanup()`, which libcurl documents as not thread safe.  nginx
/// never does that (one instance per configuration, built while the
/// configuration is read, one transaction per request in one worker process),
/// the tests take this lock instead of running in parallel.
#[cfg(test)]
pub fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|error| error.into_inner())
}

/// `ngx_http_waf_modsecurity_log()` is provided by `src/ngx_http_waf_module.c`
/// when nginx links the module.  `cargo test` links the crate on its own, so
/// the tests bring a no-op of the symbol along.
#[cfg(test)]
mod test_glue {
    use std::os::raw::{c_char, c_void};

    #[no_mangle]
    pub extern "C" fn ngx_http_waf_modsecurity_log(_log: *mut c_void, _message: *const c_char) {}
}
