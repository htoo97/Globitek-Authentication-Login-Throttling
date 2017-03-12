<?php
require_once('../../../private/initialize.php');
require_login();

if(!isset($_GET['id'])) {
  redirect_to('index.php');
}
$users_result = find_user_by_id($_GET['id']);
// No loop, only one result
$user = db_fetch_assoc($users_result);

// Set default values for all variables the page needs.
$errors = array();
$password_errors = array();

if(is_post_request() && request_is_same_domain()) {
  ensure_csrf_token_valid();

  // Confirm that values are present before accessing them.
  if(isset($_POST['first_name'])) { $user['first_name'] = h($_POST['first_name']); }
  if(isset($_POST['last_name'])) { $user['last_name'] = h($_POST['last_name']); }
  if(isset($_POST['username'])) { $user['username'] = h($_POST['username']); }
  if(isset($_POST['email'])) { $user['email'] = h($_POST['email']); }
  if (isset($_POST['password'])) { $user['password'] = h($_POST['password']);}
  if (isset($_POST['confirmPassword'])) { $user['confirmPassword'] = h($_POST['confirmPassword']);}

  // PASSWORD VALIDATIONS
  // blank password
  if (is_blank($user['password'])) {
    $password_errors[] = "Password cannot be blank.";
  }
  // blank password confirmation
  if (is_blank($user['confirmPassword'])) {
    $password_errors[] = "Password confirmation cannot be blank.";
  }
  // password and confirm password don't match
  if ($user['password'] != $user['confirmPassword']) {
    $password_errors[] = "Password and confirm password don't match.";
  }
  // password is not at least 12 characters long
  if (!has_length($user['password'], ['min' => 12, 'max' => 255])) {
    $password_errors[] = "Password is not at least 12 characters long.";
  }
  // Upper, lower, number, symbol - 1 each
  if (!preg_match('/[A-Z]/', $user['password']) || !preg_match('/[a-z]/', $user['password']) || !preg_match('/[0-9]/', $user['password']) || !preg_match('/[~!@#$%^&*+=]/', $user['password'])) {
    $password_errors[] = "Password does not contain at least one uppercase letter, one lowercase letter, one number and one symbol.";
  }

  if (empty($password_errors)) {
    $user['password'] = password_hash($user['password'], PASSWORD_BCRYPT);
    $result = update_user($user);
    if($result === true) {
      redirect_to('show.php?id=' . $user['id']);
    }
    else {
      $errors = $result;
    }
  }
  else {
    $errors = validate_user($user);
    $errors = array_merge($errors, $password_errors);
  }

}
?>
<?php $page_title = 'Staff: Edit User ' . $user['first_name'] . " " . $user['last_name']; ?>
<?php include(SHARED_PATH . '/staff_header.php'); ?>

<div id="main-content">
  <a href="index.php">Back to Users List</a><br />

  <h1>Edit User: <?php echo h($user['first_name']) . " " . h($user['last_name']); ?></h1>

  <?php echo display_errors($errors); ?>

  <form action="edit.php?id=<?php echo h(u($user['id'])); ?>" method="post">
    <?php echo csrf_token_tag(); ?>
    First name:<br />
    <input type="text" name="first_name" value="<?php echo h($user['first_name']); ?>" /><br />
    Last name:<br />
    <input type="text" name="last_name" value="<?php echo h($user['last_name']); ?>" /><br />
    Username:<br />
    <input type="text" name="username" value="<?php echo h($user['username']); ?>" /><br />
    Email:<br />
    <input type="text" name="email" value="<?php echo h($user['email']); ?>" /><br />
    Password:<br />
    <input type="password" name="password" value="" /><br />
    Confirm Password:<br />
    <input type="password" name="confirmPassword" value="" /><br />
    <br />
    <?php echo "Passwords should be at least 12 characters and include at least one uppercase letter, lowercase letter, number, and symbol.";?>
    <br />
    <br />
    <input type="submit" name="submit" value="Update"  />
  </form>

</div>

<?php include(SHARED_PATH . '/footer.php'); ?>
