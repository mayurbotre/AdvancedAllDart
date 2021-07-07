import 'dart:io';
import 'dart:convert';
import 'dart:async';
import 'dart:math';
import 'dart:typed_data';
import 'package:archive/archive.dart';
import 'package:archive/archive_io.dart';
import 'package:path/path.dart' as p;
import 'package:http/http.dart' as http;
import 'package:pointycastle/pointycastle.dart';

import 'package:AdvancedAllDart/AdvancedAllDart.dart' as AdvancedAllDart;
int count=0;
void main(List<String> arguments) async {
  print('OS: ${Platform.operatingSystem} ${Platform.version}');

  if(Platform.isLinux){
    print('Run Linux code.');
  }
  else if(Platform.isWindows){
    print('Run Windows code.');
  }
  else{
    print('Run all');
  }

  print('Path ${Platform.script.path}');
  print('Dart ${Platform.executable}');

  print('Env ');
  Platform.environment.keys.forEach((keys){
    print('$keys ${Platform.environment.keys}');
  });

  Process.run('C:\\windows\\System32\\notepad.exe', ['']).then((ProcessResult res){
    print(res.stdout);
    print('Exit code ${res.exitCode}');
  });

  Process.start('C:\\windows\\System32\\notepad.exe', ['']).then((Process res){
    res.stdout.transform(utf8.decoder).listen((data){print(data);});
    res.stdin.writeln('Hello world');
    Process.killPid(res.pid);

    res.exitCode.then((int code){
      print('Exit code ${code}');
      //exit(0);
    });
  });

  //asynchronous programming

  //Timers and callbacks

  Duration duration = new Duration(seconds: 1);
  Timer timer=new Timer.periodic(duration, timeout);
  print('Started ${getTime()}');


  //futures

  String path=Directory.current.path+'/test.txt';
  print('Appending to ${path}');

  File file=new File(path);
  Future<RandomAccessFile> f=file.open(mode:FileMode.append);
  f.then((RandomAccessFile raf){
    print('File has been opened');
    raf.writeString('Hello World!').then((value){
      print('File has been appended successfully');
      
    }).catchError(()=>print('An error occured')).whenComplete(()=>raf.close());

  });

  print('********************************************');


  print('Starting...');

  File file1=await appendFile();

  print('Appended to file ${file1.path}');

  print('Ending...');

  print('*********************************************');


  //Compression

  /*String data=' ';
  for(int i=0;i<10;i++){
    data=data+'Hello World!\r\n';
  }*/
  var original=utf8.encode(generateData());
  var compressed=gzip.encode(original);
  var decompressed=gzip.decode(compressed);

  print('Original ${original.length} in bytes ');
  print('Compressed ${compressed.length} in bytes ');
  print('Decompressed ${decompressed.length} in bytes ');

  String decoded=utf8.decode(decompressed);
  //assert(data==decoded);
  //print(decoded);


  int zlib=testCompress(ZLIB);
  int gzip1=testCompress(GZIP);

  print('ZLIB ${zlib}');
  print('gzip ${gzip1}');

  //archive encoder

  /*final bytes = File('test.zip').readAsBytesSync();

  // Decode the Zip file
  final archive = ZipDecoder().decodeBytes(bytes);

  // Extract the contents of the Zip archive to disk.
  for (final file in archive) {
    final filename = file.name;
    if (file.isFile) {
      final data = file.content as List<int>;
      File('out/' + filename)
        ..createSync(recursive: true)
        ..writeAsBytesSync(data);
    } else {
      Directory('out/' + filename)
        ..create(recursive: true);
    }
  }

  // Encode the archive as a BZip2 compressed Tar file.
  final tar_data = TarEncoder().encode(archive);
  final tar_bz2 = BZip2Encoder().encode(tar_data);

  // Write the compressed tar file to disk.
  final fp = File('test.tbz');
  fp.writeAsBytesSync(tar_bz2);

  // Zip a directory to out.zip using the zipDirectory convenience method
  var encoder = ZipFileEncoder();
  encoder.zipDirectory(Directory('out'), filename: 'out.zip');

  // Manually create a zip of a directory and individual files.
  encoder.create('out2.zip');
  encoder.addDirectory(Directory('out'));
  encoder.addFile(File('test.zip'));
  encoder.close();*/

  /*
  //zip unzip code
  List<String> file2=[];
  Directory.current.listSync().forEach((FileSystemEntity fse){
    if(fse.statSync().type==FileSystemEntityType.file) {
      file2.add(fse.path);
    }
  });
  String zipFile='C:\\Users\\MAYUR\\Desktop\\test.zip';
  zip(file2,zipFile);

  unzip(zipFile,'C:\\Users\\MAYUR\\Desktop');*/

  //Encryption

  Digest digest=new Digest('SHA-256');
  String value1='Hello world!';

  Uint8List data=new Uint8List.fromList(utf8.encode(value1));
  Uint8List hash=digest.process(data);

  print(hash);
  print(base64.encode(hash));

  String password='Password';

  var salt=createUint8ListFromString('Salt');
  var pkcs=new KeyDerivator('SHA-1/HMAC/PBKDF2');
  var params=new Pbkdf2Parameters(salt, 100, 16);
  pkcs.init(params);
  Uint8List key=pkcs.process(createUint8ListFromString(password));
  display('Key value ', key);


  print(randomBytes(8));
  print(randomBytes(16));

  //Stream cipher
  print('Stream cipher:-');
  final keybytes=randomBytes(16);
  final key1=new KeyParameter(keybytes);
  final iv=randomBytes(8);
  final params1=new ParametersWithIV(key1, iv);

  StreamCipher cipher=new StreamCipher('Salsa20');
  cipher.init(true,params1);

  //Encrypt
  String plainText='Hello World!';
  Uint8List plain_data=createUint8ListFromString(plainText);
  Uint8List encrypted_data=cipher.process(plain_data);

  //Decrypt
  cipher.reset();
  cipher.init(false, params1);
  Uint8List decrypted_data=cipher.process(encrypted_data);

  display('Plain Text ',plain_data);
  display('Encrypted Data ',encrypted_data);
  display('Decrypted Data ',decrypted_data);

  //Function eq=const ListEquality().equals;
  //assert(eq(encrypted_data,decrypted_data));

  print(utf8.decode(decrypted_data));
  print('**************************************');
  //Block Cipher

  print('Block Cipher:-');
  final key2=randomBytes(16);
  final params2=new KeyParameter(key2);

  BlockCipher cipher2=new BlockCipher('AES');
  cipher2.init(true,params2);

  //Encrypt
  String plainText1='Hello World!';
  Uint8List plain_data2=createUint8ListFromString(plainText1.padRight(cipher2.blockSize));
  Uint8List encrypt_data2=cipher2.process(plain_data2);

  //Decrypt
  cipher2.reset();
  cipher2.init(false, params2);
  Uint8List decrypt_data2=cipher2.process(encrypt_data2);

  display('Plain Text', plain_data2);
  display('Encrypted Data', encrypt_data2);
  display('Decrypted Data', decrypt_data2);

  print(utf8.decode(decrypt_data2).trim());

  print('****************************************');

  //socket Programming

  //tcp server
  var serverSocket=await ServerSocket.bind('127.0.0.1', 3000);
  print('Listening');
  /*await for(var socket in serverSocket){
    socket.listen((List<int> values) {
      print('${socket.remoteAddress}${socket.remotePort} = ${utf8.decode(values)}');
    });
  }*/

  //tcp client

  var socket=await Socket.connect('127.0.0.1', 3000);
  print('Connected');
  socket.write('Hello World!');
  print('Sent ...\r\nClosing');
  await socket.close();
  print('closed');


  //http get

  Uri url1=Uri.parse('http://httpbin.org');
  var response=await http.get(url1);
  print('Response status: ${response.statusCode}');
  print('Response body: ${response.body}');

  //http post

  var response2=await http.post(url1,body: 'name=Bryan&color=blue');
  print('Response status: ${response2.statusCode}');
  print('Response body: ${response2.body}');

  //UDP socket

  var datta='Hello World!';
  List<int> dataToSend=utf8.encode(datta);
  int port=3000;


  //Server
  RawDatagramSocket.bind(InternetAddress.loopbackIPv4, port).then((RawDatagramSocket udpSocket) {
    udpSocket.listen((RawSocketEvent event) {
      if(event==RawSocketEvent.read){
        Datagram? dg=udpSocket.receive();
        print(utf8.decode(dg!.data));
      }
    });

    //client
    udpSocket.send(dataToSend, InternetAddress.loopbackIPv4, port);
    print('Sent.');

  });


}

void timeout(Timer timer){
  print('Timeout ${getTime()}');

  count++;
  if(count>=5) timer.cancel();
}


String getTime(){
  DateTime dt=new DateTime.now();
  return dt.toString();
}

Future<File> appendFile(){
  File file=new File(Directory.current.path+'/test1.txt');
  DateTime now = new DateTime.now();
  return file.writeAsString(now.toString()+'\r\n',mode:FileMode.append);
}

String generateData(){
  String data='';
  for(int i=0;i<10000;i++){
    data=data+'Hello World!\r\n';
  }
  return data;
}

int testCompress(var codec){
  String data=generateData();
  var original=utf8.encode(data);
  var compressed=codec.encode(original);
  var decompressed=codec.decode(compressed);


  print('Testing  ${codec.toString()}');
  print('Original ${original.length} in bytes ');
  print('Compressed ${compressed.length} in bytes ');
  print('Decompressed ${decompressed.length} in bytes ');

  String decoded=utf8.decode(decompressed);
  //assert(data==decoded);
  //print(decoded);
  return compressed.length;
}

void zip(List<String> files,String file){
  Archive archive=new Archive();

  files.forEach((String path){
    File file=new File(path);
    ArchiveFile archiveFile=new ArchiveFile(p.basename(path),file.lengthSync(),file.readAsBytesSync());
    archive.addFile(archiveFile);


  });
  File f=new File(file);
  f.writeAsBytesSync(TarEncoder().encode(archive));
  print('Compressed');


}
void unzip(String zip,String path){

  File file=new File(path);

  Archive archive=new TarDecoder().decodeBytes(file.readAsBytesSync());

  archive.forEach((ArchiveFile archiveFile){
    File file=new File(path+'/'+archiveFile.name);
    file.createSync(recursive:true);
    file.writeAsBytesSync(archiveFile.content);
  });
  print('Decompressed...');

}


Uint8List createUint8ListFromString(String value) => new Uint8List.fromList(utf8.encode(value));

void display(String title,Uint8List val){
  print(title);
  print(val);
  print(base64.encode(val));
  print('***************************');

}

Uint8List randomBytes(int length){
  final rand=new SecureRandom('AES/CTR/AUTO-SEED-PRNG');

  final key=Uint8List(16);
  final keyParam=new KeyParameter(key);
  final params=new ParametersWithIV(keyParam, new Uint8List(16));
  rand.seed(params);
  var random=new Random();
  for(int i=0;i<random.nextInt(255);i++){
    rand.nextUint8();
  }
  var bytes=rand.nextBytes(length);
  return bytes;

}