document.addEventListener('DOMContentLoaded', function () {
  
    document.getElementById('login-form').addEventListener('submit', function(e) {
  
      let username = document.getElementById('username').value;
      let password = document.getElementById('password').value;
  
      if (username === 'admin' && password === 'admin') {
          window.location.href = '/firewall-dashboard#';
  
          document.getElementById('login-error').style.display = 'block';
      }
  });

});