<?php
    $file_name  = $_GET["poem"];
    echo "<pre>";
    echo file_get_contents( "files/" . $file_name ) . "<br>";
    echo "</pre>";
?>

<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>A Very C0oL W3bsite</title>
</head>
<body>
    I wrote some poems for you. 

    
    <form method="get">
        <input type="submit" name="poem" value="poem1.txt">
        <input type="submit" name="poem" value="poem2.txt">
        <input type="submit" name="poem" value="poem3.txt">
    </form>
    
    
</body>
</html>

<!-- Apparently flag.txt is stored in the same directory as the index, unlike the poems which seem to reside in a directory. I wonder if 
those pesky children can take advantage of that somehow -->