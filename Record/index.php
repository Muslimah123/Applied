
<!DOCTYPE html>
<html>
<head>
  <title>Record Page</title>
  <style>
    body {
      background-color: #f2f2f2;
      font-family: Arial, sans-serif;
      font-size: 16px;
      line-height: 1.5;
    }
    .container {
      max-width: 800px;
      margin: 0 auto;
      padding: 40px;
      background-color: #fff;
      box-shadow: 0 0 10px rgba(0, 0, 0, 0.2);
    }
    
    h1 {
      font-size: 32px;
      margin-bottom: 20px;
    }
    label {
      display: block;
      margin-bottom: 10px;
    }
    audio {
      display: block;
      margin-bottom: 20px;
    }
    button {
      font-size: 16px;
      padding: 10px 20px;
      border: none;
      border-radius: 5px;
      background-color: #007bff;
      color: #fff;
      cursor: pointer;
    }
    button:active {
      background-color: #0062cc;
    }
    .process-btn {
      margin-top: 20px;
    }
    a {
  text-decoration: none;
  color: white;
}

  </style>
</head>
<body>
  <div class="container">
    <h1>Record your voice</h1>
    <label for="record-btn">Record:</label>
    <button id="record-btn">Start</button>
    <button id="stop-btn" disabled>Stop</button>
    <audio></audio>
    <label for="recorded-text">Recorded Text:</label>
    <div id="recorded-text"></div>
    <button class="process-btn" id="process-btn" disabled><a href="../dashboard/index.php">Process Text</a></button>
  </div>
  <script>
    var rec;
    var audio = document.querySelector('audio');
    var recordButton = document.getElementById('record-btn');
    var stopButton = document.getElementById('stop-btn');
    var recordedText = document.getElementById('recorded-text');
    var processButton = document.getElementById('process-btn');

    function startRecording() {
      var constraints = { audio: true, video: false };

      navigator.mediaDevices.getUserMedia(constraints).then(function(stream) {
        rec = new Recorder(stream);
        rec.record();
        recordButton.disabled = true;
        stopButton.disabled = false;
        processButton.disabled = true;
      }).catch(function(err) {
        console.error('Error starting recording', err);
      });
    }

    function stopRecording() {
      rec.stop();
      rec.exportWAV(function(blob) {
        audio.src = URL.createObjectURL(blob);
        audio.play();
        var reader = new FileReader();
        reader.onloadend = function() {
          recordedText.innerHTML = reader.result;
          processButton.disabled = false;
        };
        reader.readAsText(blob);
      });
      recordButton.disabled = false;
      stopButton.disabled = true;
    }

    recordButton.addEventListener('click', startRecording);
    stopButton.addEventListener('click', stopRecording);

    processButton.addEventListener('click', function() {
      var text = recordedText.innerHTML.trim();
      if (text.length > 0) {
        // Process the text here
        console.log('Text to process:', text);
        alert('Text processed!');
      } else {
        alert('Please record some text first');
      }
    });
  </script>
</body>
</html>
