<?php //início de um script PHP
 session_start(); // Inicialização da sessão
 //Memória de login em todas as páginas
 
//Importando as configurações de Banco de Dados
require_once 'configDB.php';

//Limpando os dados de entrada POST
function verificar_entrada($entrada){
   $saída = trim($entrada);//Remove espaços
   $saída = htmlspecialchars($saída);//Remove HTML
   $saída = stripcslashes($saída);//Remove barras
   return $saída; 
}
if(isset($_POST['action']) && $_POST['action'] == 'entrar'){
       
    //echo 'Entrou!!!';
    $nomeUsuário = verificar_entrada($_POST['nomeUsuario']);
    $senhaUsuário = verificar_entrada($_POST['senhaUsuario']);
    $senha = sha1($senhaUsuário);
    
    
    
   $sql = $conexão->prepare("SELECT * FROM usuario " . " WHERE nomeUsuario = ? AND senha=? ");
               
    $sql->bind_param("ss", $nomeUsuário, $senha);
    $sql->execute();
    
    $busca = $sql->fetch();// fetch = buscar
    if($busca != null){
        //Usuário e senha estão corretos
        $_SESSION['nomeUsuario'] = $nomeUsuário;
        echo 'ok';
        
        if(!empty($_POST['lembrar'])){
            setcookie('nomeUsuario',$nomeUsuário, time()+(365*24*60*60));
            setcookie('senhaUsuario',$senhaUsuário, time()+(365*24*60*60)); // 1 ano de vida em segundos 
        } else {
            //Limpa o cookie
            if (isset($_COOKIE['nomeUsuario']))
                setcookie ('nomeUsuario','');
            if (isset($_COOKIE['senhaUsuario']))
                setcookie ('senhaUsuario','');
        }
    }else {
        echo 'Falhou o login... Nome de usuário ou Senha inválidos!!!';
    }
    
} elseif(isset($_POST['action']) 
        && $_POST['action'] == 'registro'){
    // Sanitização de entradas 
    $nomeCompleto = verificar_entrada($_POST['nomeCompleto']);
    $nomeUsuário = verificar_entrada($_POST['nomeUsuario']);
    $emailUsuário = verificar_entrada($_POST['emailUsuario']);
    $senhaUsuário = verificar_entrada($_POST['senhaUsuario']);
    $senhaUsuárioConfirmar =
 verificar_entrada($_POST['senhaUsuarioConfirmar']);
    $criado = date("Y-m-d H:i:s"); //Cria uma data e hora Ano-mês-dia
    
    //Gerar um hash para as senhas
    $senha = sha1($senhaUsuário);
    $senhaConfirmar = sha1($senhaUsuárioConfirmar);
    
    //echo "Hash: " . $senha;
    
    //Conferência de senha no Back-end, no caso do javascript 
    // estar desabilitado
    if($senha != $senhaConfirmar){
        echo "As senhas não conferem";
        exit();
    }else{
        //Verificando se o usuário existe no Banco de Dados
        //Usando MySQLi prepared statment
        $sql = $conexão->prepare("SELECT nomeUsuario, email FROM "
                . "usuario WHERE nomeUsuario = ? OR "
                . "email = ?");//Evitar SQL injection
        $sql->bind_param("ss", $nomeUsuário, $emailUsuário);
        $sql->execute(); //Método do objeto $sql
        $resultado = $sql->get_result(); //Tabela do Banco
        $linha = $resultado->fetch_array(MYSQLI_ASSOC);
        if($linha['nomeUsuario'] == $nomeUsuário)
            echo "Nome {$nomeUsuário} indisponível.";
        elseif($linha['email'] == $emailUsuário)
            echo "E-mail {$emailUsuário} indisponível.";            
        else{
            //Preparar a inserção no Banco de dados
            $sql = 
                $conexão->prepare("INSERT INTO usuario "
                . "(nome, nomeUsuario, email, senha, criado) "
                . "VALUES(?, ?, ?, ?, ?)");
            $sql->bind_param("sssss", $nomeCompleto, $nomeUsuário,
                    $emailUsuário, $senha, $criado);
            if($sql->execute())
                echo "Cadastrado com sucesso!";
            else
                echo "Algo deu errado. Por favor, tente novamente.";            
        }
    }
    
}elseif(isset($_POST['action']) 
        && $_POST['action'] == 'gerar'){
    
    $emailGerarSenha= verificar_entrada($_POST['emailGerarSenha']);
    $sql = $conexão->prepare("SELECT idUsuario  FROM usuario where email=?");
    
    $sql->bind_param("s",$emailGerarSenha);
    $sql->execute();
    $resposta = $sql->get_result();
    if ($resposta->num_rows > 0){# E-mail existe no banco de dados
        # Geração do token, 10 caracteres aleatórios
        
        
        $frase = "gerou o token afadsfdfdfafawefafafaseffasf";
        $palavra_secreta = str_shuffle($frase);
        $token = substr($palavra_secreta, 0,10);
        
        #Atualização do banco de dados, passando o token e a validade
        $sql = $conexão->prepare("UPDATE usuario set token=?, tokenExpirado=DATE_ADD(now(), INTERVAL 5 MINUTE) WHERE email=?");
        
        $sql->bind_param("ss", $token, $emailGerarSenha);
        
        $sql->execute();
        
        # SIMULAÇÃO DO ENVIO DO LINK POR E-MAIL, O CÓDIGO ABAIXO DEVE SER ENVIADO POR E-MAIL.
        
        $link = "<p><a href='http://localhost:8080/sistemaDeLogin/gerarSenha.php?email=$emailGerarSenha&token=$token'>Clique aqui</a> para gerar uma nova senha.</p>";
        echo $link;
        
    } else {# E-mail nao existe
        echo "<strong class='text-danger> E-mail não encontrado</strong>";    
    }
    
    
    
    
}else    header ("location:index.php");
//redireciona ao acessar este arquivo diretamente
//só funciona quando nada estiver impresso na tela

    

