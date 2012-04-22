<?php
/**
* Function For change Hash algo in application 
*
*
* @Version		0.1
* @Author		Sanguinarius
* @Contact		sanguinarius.contact@gmail.com
* @Copyright	2011-2069 Kalkulators knights and sanguinarius
* @Standard		http://pear.php.net/manual/en/standards.php
*
**/


require 'PasswordHash.php';
class Hash_Algo
{

	// Attributs
	var $str_len = 12; // Default lenght for pass
		
	var $lenght_salt = 128; // Default lenght for salt
	var $salt1;
	var $salt2;
	
	var $status_error = 0;
	var $list_error;
	
	var $list_algo;
	
	// Méthodes
	function __construct($len_salt="", $len_str="") 
	{
		if($len_str != "") 
		{
			if(!is_int($len_str))
			{
				$len_str = intval($len_str);
			}
			$this->str_len = $len_str;
		}
		if ($len_salt != "")
		{
			if (!is_int($len_salt))
			{
				$len_salt = intval($len_salt);
			}
			$this->lenght_salt = $len_salt;
		}
		$this->salt1 = $this->_genRandomString($this->lenght_salt);
		$this->salt2 = $this->_genRandomString($this->lenght_salt);
		$this->_listAlgo();
	}
	
	/**
	* General Function
	**/
	private function _listAlgo()
	{
		$this->list_algo["Njord"] = "phpass(sha512(sha512(sha512(SALT1))+sha512(sha512(sha512(STRING)))+sha512(sha512(SALT2))))";
		$this->list_algo["Freyr"] = "phpass(sha256(sha256(sha512(SALT1))+sha512(sha512(sha256(STRING)))+sha384(sha512(SALT2))+sha512(sha512(SALT1))))";
	}
	private function _genRandomString($len) 
	{
		if(!is_int($len)) 
		{
			$len = intval($len);
		} 
		$salt = '';
		srand((float) microtime() * 10000000);
		for ($i = 0; $i < $len; $i++) 
		{
			$salt .= chr(mt_rand(33, 126));
		}
		return $salt;
	}
	private function _checkStringValidity($str)
	{
		if(strlen($str) < $this->str_len)
		{
			$this->list_error[] = "Error : Password is too short use ".$this->str_len." chars minimum.";
			$this->status_error = 1;
		}
	}
	private function _checkAlgoValidity($algo)
	{
		if (!array_key_exists($algo, $this->list_algo)) 
		{
			$this->list_error[] = "Error : Algo is not valid, choose a valid algo.";
			$this->status_error = 1;
		}
	}
	function hashPass($txt, $algo)
	{
		$this->_checkStringValidity($txt);
		$this->_checkAlgoValidity($algo);
		if($this->status_error == 1)
		{
			$this->printError();
		}
		else
		{
			$base_hash = $this->$algo($txt);
			if(is_array($base_hash))
			{
				return $base_hash[1];
			}
			else
			{
				return $base_hash;
			}
		}
	}	
	function checkPass($enter_pass, $algo, $phpass, $recover_salt1, $recover_salt2)
	{
		$this->_checkStringValidity($enter_pass);
		$this->_checkAlgoValidity($algo);
		if($this->status_error == 1)
		{
			$this->printError();
		}
		else
		{
			$this->salt1 = $recover_salt1;
			$this->salt2 = $recover_salt2;
			$base_hash = $this->$algo($txt);
			if(is_array($base_hash))
			{
				$check = $t_hasher->CheckPassword($base_hash[0], $phpass);
				return $check;
			}
			else
			{
				$check = $t_hasher->CheckPassword($base_hash, $phpass);
				return $check;
			}
		}
	}
	/**
	* Algo Function
	**/
	private function _genPhpass($text)
	{
		$t_hasher = new PasswordHash(8, TRUE);
		$hash = $t_hasher->HashPassword($text);
		return $hash;
	}
	private function Njord($text)
	{
		$way1 = hash('sha512',hash('sha512',hash('sha512',$this->salt1)).hash('sha512',hash('sha512',hash('sha512',$text))).hash('sha512',hash('sha512',$this->salt2)));
		$phpass = $this->_genPhpass($way1);
		return array($way1, $phpass);
	}
	private function Freyr($text)
	{
		$way1 = hash('sha256',hash('sha256',hash('sha512',$this->salt1)).hash('sha512',hash('sha512',hash('sha256',$text))).hash('sha384',hash('sha512',$this->salt2)).hash('sha512',hash('sha512',$this->salt1)));
		$phpass = $this->_genPhpass($way1);
		return array($way1, $phpass);
	}
	

	/**
	* Print Function
	**/
	function printAlgo()
	{
		foreach ($this->list_algo as $algos => $struc) 
		{
			echo "Nom : $algos -----> Structure : $struc \n";
		}
	}
	function printError()
	{
		foreach ($this->list_error as $mess) 
		{
			echo $mess."\n";
		}
	}
	function help()
	{
	
	}
}
?>