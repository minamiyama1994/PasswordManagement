import qualified Crypto.Cipher.Types as CCT
import qualified Crypto.Cipher.AES as CCA
import qualified Data.ByteString as DB
import qualified Data.ByteString.Char8 as DBC

alignInput :: ( Bounded a ) => [ a ] -> [ a ]
alignInput as = as ++ ( take ( 16 - ( length as `mod` 16 ) ) $ repeat minBound )

main :: IO ( )
main = do
    putStr "Input Password > "
    password <- getLine >>= return . DB.pack . alignInput . DB.unpack . DBC.pack
    aesFileContents <- DB.readFile ".PM" >>= return . DB.pack . alignInput . DB.unpack
    ( Right decodeFileContents ) <- return $ CCT.makeKey password >>= return . ( \ key -> CCT.cbcDecrypt ( CCT.cipherInit key ) ( CCT.nullIV :: CCT.IV CCA.AES ) aesFileContents )
    putStr "Register? Inquiry? [R/I] > "
    ri <- getLine
    case ri of
        "R" -> do
            putStr "Key >"
            key <- getLine
            putStr "Value > "
            value <- getLine
            kvs <- return $ DB.pack . alignInput . DB.unpack . DBC.pack $ show $ ( key , value ) : filter ( \ ( k , _ ) -> k /= key ) ( read $ filter ( /= '\x00' ) ( DBC.unpack decodeFileContents ) )
            ( Right encodeFileContents ) <- return $ CCT.makeKey password >>= return . ( \ key -> CCT.cbcEncrypt ( CCT.cipherInit key ) ( CCT.nullIV :: CCT.IV CCA.AES ) kvs )
            DB.writeFile ".PM" encodeFileContents
        "I" -> do
            putStr "Key >"
            key <- getLine
            [ ( _ , value ) ] <- return $ filter ( \ ( k , _ ) -> k == key ) ( read $ filter ( /= '\x00' ) ( DBC.unpack decodeFileContents ) )
            putStr "Value > "
            putStr value
