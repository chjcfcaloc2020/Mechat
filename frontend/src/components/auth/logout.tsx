import { Button } from "@/components/ui/button"
import { useAuthStore } from "@/stores/useAuthStore"
import { useNavigate } from "react-router"

const Logout = () => {
  const { signOut } = useAuthStore()
  const navigate = useNavigate()

  const handleLogOut = async () => {
    try {
      await signOut()
      navigate("/signin")
    } catch (error) {
      console.error("Error during logout:", error)
    }
  }

  return (
    <Button onClick={handleLogOut}>Logout</Button>
  )
}

export default Logout