pragma solidity >=0.4.22 <=0.6.0;

contract federated{

    uint256 constant broker_number  = 6;
    mapping(uint256 =>  bytes []) public authorization;
    mapping(bytes32 => bytes32) public task_index;
    uint256 public searchtok;
    bytes32 [] public cipher;
    uint public searchfbpie;
    bytes public pp;
    bytes32 [] returnC;
    bytes32 state;
    bytes exp1;
    bytes concat1;
    bytes aut;

    // constructor  () public {
    //     pp = hex'000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001';
    //     task_index[0x0000000000000000000000000000000000000000000000000000000000000000]=0x0000000000000000000000000000000000000000000000000000000000000001;
    //     bytes memory test = hex"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001";
    //     authorization[0].push(test);
    // }

    ////授权
    function setauthorize(uint256 tok, bytes authori) public{
        authorization[tok].push(authori);
    }

     function get_authorize(uint256 tok, uint256 index ) public view returns (bytes){
        return authorization[tok][index];
    }


    function set_taskindex(bytes32 [] memory token, bytes32 [] memory value, uint len) public{
        for(uint i=0; i<len; i++) {
            bytes32 m=token[i];
            bytes32 n=value[i];
            task_index[m]=n;
        }
    }

     //build task index
     function settask(bytes32 ctoken, bytes32 dhash) public{
        task_index[ctoken]=dhash;
    }


    function get_taskindex(bytes32 tok) public view returns (bytes32){
        return task_index[tok];
    }


    //search token
     //  计算幂
    function expmod(bytes g, uint256 x, bytes p) public view returns ( bytes) {
      require(p.length == 384,"unqualified length of p");
      require(g.length == 384,"unqualified length of g");
      bytes memory input = abi.encodePacked(bytes32(g.length),bytes32(0x20),bytes32(p.length),g,bytes32(x),p);
    //   bytes memory result = new bytes(384);
        bytes memory result = new bytes(384);
      bytes memory pointer = new bytes(384);
      assembly {
          if iszero(staticcall(sub(gas, 2000), 0x05, add(input,0x20), 0x380, add(pointer,0x20), 0x180 )) {
             revert(0, 0)
          }
      }
      for(uint i =0; i<12;i++) {
          bytes32 value;
          uint256 start = 32*i;
          assembly {
              value := mload(add(add(pointer,0x20),start))
          }
        //   return value;
          for(uint j=0;j<32;j++) {
              result[start+j] = value[j];
          }
      }
      return result;
    }



    function setP(bytes p) public{
        pp=p;
    }


    //int 转 bytes
    // function toBytes(uint256 x) public view returns (bytes32  b) {

    function toBytes(uint256 x) public view returns (bytes32  b) {

     return bytes32(x);

}



    //字符串拼接
    function concat(bytes a, bytes32 b) public view returns (bytes memory) {
        return abi.encodePacked(a,b);
    }

    //search function
     function get_searchtoke (uint256 tok, uint256 fbpie) public  {
         for(uint i=0;i<broker_number;i++){
             bytes memory autho=authorization[fbpie][i];
             //指数
             bytes memory exp=expmod(autho, tok, pp);
             uint256 c=0;
             bytes memory concatination=concat(exp,toBytes(c));

             bytes32  G1label=  keccak256(abi.encodePacked(concatination));

             bytes32 stop = 0x0;
             while (task_index[G1label]!= stop){
                 bytes32  ciphertext=task_index[G1label]^G1label;
                 returnC.push(ciphertext);
                // ctest.push(ciphertext);
                 c=c+1;
                 concatination=concat(exp,toBytes(c));
                 G1label=keccak256(abi.encodePacked(concatination));
             }
         }
        //  return ctest;
     }


    function  get_returnC() public view returns (bytes32[]){
        return returnC;
    }

    function try1 (uint256 tok, uint256 fbpie) public returns (bytes32)  {

        bytes memory autho=authorization[fbpie][0];
        aut=autho;
            //指数
        bytes memory exp=expmod(autho, tok, pp);

        exp1=exp;
        uint256 c=0;
        bytes memory concatination=concat(exp,toBytes(c));
        concat1=concatination;

        bytes32 G1label=  keccak256(abi.encodePacked(concatination));
        state=G1label;
        return state;
    }

    // function get_autho()public view returns (bytes){
    //     return aut;
    // }

    // function get_exp1() public view returns (bytes){
    //     return exp1;
    // }

    // function get_concat1() public view returns (bytes){
    //     return concat1;
    // }


    // function get_G1label() public view returns (bytes32){
    //     return state;
    // }

    }