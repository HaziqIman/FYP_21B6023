document.addEventListener('DOMContentLoaded', function () {
  
    document.getElementById('login-form').addEventListener('submit', function(e) {
  
      // Get the form data
      let username = document.getElementById('username').value;
      let password = document.getElementById('password').value;
  
      // Example login check (you would normally send this to the server)
      if (username === 'admin' && password === 'admin') {
          window.location.href = '/firewall-dashboard#';
  
          document.getElementById('login-error').style.display = 'block';
      }
  });

});